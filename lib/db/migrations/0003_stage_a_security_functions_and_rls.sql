BEGIN;

SET LOCAL ROLE workos_schema_owner;

CREATE OR REPLACE FUNCTION workos_security.setting_uuid(setting_name text)
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
  raw_value text;
BEGIN
  raw_value := current_setting(setting_name, true);
  IF raw_value IS NULL OR raw_value = '' THEN
    RETURN NULL;
  END IF;
  RETURN raw_value::uuid;
EXCEPTION WHEN invalid_text_representation THEN
  RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION workos_security.active_context_allows(
  row_tenant_id uuid,
  row_workspace_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, workos
AS $$
  SELECT
    current_setting('workos.access_mode', true) = 'NORMAL'
    AND workos_security.setting_uuid('workos.user_id') IS NOT NULL
    AND workos_security.setting_uuid('workos.tenant_id') = row_tenant_id
    AND workos_security.setting_uuid('workos.workspace_id') = row_workspace_id
    AND EXISTS (
      SELECT 1
      FROM workos.workspace_memberships membership
      WHERE membership.tenant_id = row_tenant_id
        AND membership.workspace_id = row_workspace_id
        AND membership.user_id = workos_security.setting_uuid('workos.user_id')
        AND membership.status = 'ACTIVE'
        AND membership.effective_from <= now()
        AND (membership.effective_to IS NULL OR membership.effective_to > now())
        AND membership.context_version::text = current_setting('workos.context_version', true)
    )
    AND (
      workos_security.setting_uuid('workos.assignment_id') IS NULL
      OR EXISTS (
        SELECT 1
        FROM workos.operator_assignments assignment
        WHERE assignment.id = workos_security.setting_uuid('workos.assignment_id')
          AND assignment.tenant_id = row_tenant_id
          AND assignment.workspace_id = row_workspace_id
          AND assignment.operator_user_id = workos_security.setting_uuid('workos.user_id')
          AND assignment.status = 'ACTIVE'
          AND assignment.effective_from <= now()
          AND (assignment.effective_to IS NULL OR assignment.effective_to > now())
          AND assignment.context_version::text = current_setting('workos.assignment_context_version', true)
      )
    );
$$;

CREATE OR REPLACE FUNCTION workos_security.system_job_allows(
  row_tenant_id uuid,
  row_workspace_id uuid,
  row_resource_id uuid,
  required_job_type text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, workos_control
AS $$
  SELECT
    current_setting('workos.access_mode', true) = 'SYSTEM_JOB'
    AND workos_security.setting_uuid('workos.system_job_id') IS NOT NULL
    AND workos_security.setting_uuid('workos.claim_token') IS NOT NULL
    AND workos_security.setting_uuid('workos.tenant_id') = row_tenant_id
    AND workos_security.setting_uuid('workos.workspace_id') = row_workspace_id
    AND EXISTS (
      SELECT 1
      FROM workos_control.job_envelopes job
      WHERE job.id = workos_security.setting_uuid('workos.system_job_id')
        AND job.claim_token = workos_security.setting_uuid('workos.claim_token')
        AND job.tenant_id = row_tenant_id
        AND job.workspace_id = row_workspace_id
        AND job.job_type = required_job_type
        AND job.resource_id IS NOT DISTINCT FROM row_resource_id
        AND job.claim_state = 'CLAIMED'
        AND job.lease_expires_at > now()
    );
$$;

CREATE OR REPLACE FUNCTION workos_security.get_access_catalog_for_current_user()
RETURNS TABLE (
  tenant_id uuid,
  tenant_name text,
  workspace_id uuid,
  workspace_name text,
  workspace_type text,
  membership_role workos.membership_role,
  assignment_id uuid,
  represented_principal_id uuid,
  represented_principal_name text,
  context_version bigint,
  assignment_context_version bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, workos
AS $$
  SELECT
    tenant.id,
    tenant.name,
    workspace.id,
    workspace.name,
    workspace.workspace_type,
    membership.role,
    assignment.id,
    principal.id,
    principal.display_name,
    membership.context_version,
    assignment.context_version
  FROM workos.workspace_memberships membership
  JOIN workos.workspaces workspace
    ON workspace.tenant_id = membership.tenant_id
   AND workspace.id = membership.workspace_id
  JOIN workos.tenants tenant ON tenant.id = membership.tenant_id
  LEFT JOIN workos.operator_assignments assignment
    ON assignment.tenant_id = membership.tenant_id
   AND assignment.workspace_id = membership.workspace_id
   AND assignment.operator_user_id = membership.user_id
   AND assignment.status = 'ACTIVE'
   AND assignment.effective_from <= now()
   AND (assignment.effective_to IS NULL OR assignment.effective_to > now())
  LEFT JOIN workos.operator_assignment_principals assignment_principal
    ON assignment_principal.tenant_id = assignment.tenant_id
   AND assignment_principal.workspace_id = assignment.workspace_id
   AND assignment_principal.assignment_id = assignment.id
  LEFT JOIN workos.principals principal
    ON principal.tenant_id = assignment_principal.tenant_id
   AND principal.workspace_id = assignment_principal.workspace_id
   AND principal.id = assignment_principal.principal_id
   AND principal.status = 'ACTIVE'
  WHERE current_setting('workos.access_mode', true) = 'ACCESS_CATALOG'
    AND membership.user_id = workos_security.setting_uuid('workos.user_id')
    AND membership.status = 'ACTIVE'
    AND membership.effective_from <= now()
    AND (membership.effective_to IS NULL OR membership.effective_to > now())
    AND workspace.status = 'ACTIVE'
    AND tenant.status = 'ACTIVE'
  ORDER BY tenant.name, workspace.name, principal.display_name NULLS FIRST;
$$;

CREATE OR REPLACE FUNCTION workos_security.open_portfolio_context(p_purpose text)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, workos
AS $$
DECLARE
  context_id uuid := gen_random_uuid();
  current_user_id uuid := workos_security.setting_uuid('workos.user_id');
  assignment_fingerprint text;
BEGIN
  IF current_setting('workos.access_mode', true) <> 'ACCESS_CATALOG'
    OR current_user_id IS NULL
    OR length(trim(p_purpose)) < 3 THEN
    RAISE EXCEPTION 'invalid portfolio context request';
  END IF;

  SELECT encode(
    digest(
      coalesce(string_agg(assignment.id::text || ':' || assignment.context_version::text, ',' ORDER BY assignment.id), ''),
      'sha256'
    ),
    'hex'
  )
  INTO assignment_fingerprint
  FROM workos.operator_assignments assignment
  WHERE assignment.operator_user_id = current_user_id
    AND assignment.status = 'ACTIVE'
    AND assignment.effective_from <= now()
    AND (assignment.effective_to IS NULL OR assignment.effective_to > now());

  INSERT INTO workos.portfolio_contexts (id, user_id, purpose, snapshot_hash, expires_at)
  VALUES (context_id, current_user_id, p_purpose, assignment_fingerprint, now() + interval '15 minutes');

  INSERT INTO workos.portfolio_context_assignments (
    portfolio_context_id, tenant_id, workspace_id, assignment_id
  )
  SELECT context_id, tenant_id, workspace_id, id
  FROM workos.operator_assignments
  WHERE operator_user_id = current_user_id
    AND status = 'ACTIVE'
    AND effective_from <= now()
    AND (effective_to IS NULL OR effective_to > now());

  RETURN context_id;
END
$$;

CREATE OR REPLACE FUNCTION workos_security.get_portfolio_metadata(p_portfolio_context_id uuid)
RETURNS TABLE (
  tenant_id uuid,
  tenant_name text,
  workspace_id uuid,
  workspace_name text,
  assignment_id uuid,
  category text,
  urgency workos.attention_priority,
  age_seconds bigint,
  sla_due_at timestamptz,
  status text,
  refreshed_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, workos
AS $$
  SELECT
    projection.tenant_id,
    tenant.name,
    projection.workspace_id,
    workspace.name,
    projection.assignment_id,
    projection.category,
    projection.urgency,
    projection.age_seconds,
    projection.sla_due_at,
    projection.status,
    projection.refreshed_at
  FROM workos.portfolio_contexts context
  JOIN workos.portfolio_context_assignments context_assignment
    ON context_assignment.portfolio_context_id = context.id
  JOIN workos.operator_assignments assignment
    ON assignment.tenant_id = context_assignment.tenant_id
   AND assignment.workspace_id = context_assignment.workspace_id
   AND assignment.id = context_assignment.assignment_id
  JOIN workos.portfolio_metadata_projection projection
    ON projection.tenant_id = assignment.tenant_id
   AND projection.workspace_id = assignment.workspace_id
   AND projection.assignment_id = assignment.id
  JOIN workos.workspaces workspace
    ON workspace.tenant_id = projection.tenant_id
   AND workspace.id = projection.workspace_id
  JOIN workos.tenants tenant ON tenant.id = projection.tenant_id
  WHERE current_setting('workos.access_mode', true) = 'ACCESS_CATALOG'
    AND context.id = p_portfolio_context_id
    AND context.user_id = workos_security.setting_uuid('workos.user_id')
    AND context.expires_at > now()
    AND assignment.operator_user_id = context.user_id
    AND assignment.status = 'ACTIVE'
    AND assignment.effective_from <= now()
    AND (assignment.effective_to IS NULL OR assignment.effective_to > now())
  ORDER BY projection.urgency DESC, projection.sla_due_at NULLS LAST;
$$;

CREATE OR REPLACE FUNCTION workos_control.enqueue_job(
  p_job_type text,
  p_resource_id uuid,
  p_due_at timestamptz,
  p_dedupe_key text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, workos_control
AS $$
DECLARE
  job_id uuid := gen_random_uuid();
  current_tenant_id uuid := workos_security.setting_uuid('workos.tenant_id');
  current_workspace_id uuid := workos_security.setting_uuid('workos.workspace_id');
BEGIN
  IF NOT workos_security.active_context_allows(current_tenant_id, current_workspace_id) THEN
    RAISE EXCEPTION 'active context does not permit enqueue';
  END IF;
  IF p_job_type NOT IN ('OUTBOX_DELIVERY', 'WORK_RECONCILE', 'TASK_RECONCILE', 'PORTFOLIO_REFRESH') THEN
    RAISE EXCEPTION 'unsupported job type';
  END IF;
  IF length(trim(p_dedupe_key)) < 8 THEN
    RAISE EXCEPTION 'invalid dedupe key';
  END IF;

  INSERT INTO workos_control.job_envelopes (
    id, tenant_id, workspace_id, job_type, resource_id, due_at, dedupe_key
  )
  VALUES (
    job_id, current_tenant_id, current_workspace_id, p_job_type,
    p_resource_id, p_due_at, p_dedupe_key
  )
  ON CONFLICT (tenant_id, workspace_id, dedupe_key)
  DO UPDATE SET updated_at = workos_control.job_envelopes.updated_at
  RETURNING id INTO job_id;

  RETURN job_id;
END
$$;

CREATE OR REPLACE FUNCTION workos_control.claim_due_job(
  p_worker_id text,
  p_job_types text[],
  p_lease_seconds integer DEFAULT 60
)
RETURNS TABLE (
  job_id uuid,
  tenant_id uuid,
  workspace_id uuid,
  job_type text,
  resource_id uuid,
  due_at timestamptz,
  claim_token uuid
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, workos_control, workos
AS $$
DECLARE
  claimed workos_control.job_envelopes%ROWTYPE;
BEGIN
  IF length(trim(p_worker_id)) < 3 OR p_lease_seconds < 5 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'invalid worker claim';
  END IF;
  IF p_job_types IS NULL
    OR NOT p_job_types <@ ARRAY['OUTBOX_DELIVERY', 'WORK_RECONCILE', 'TASK_RECONCILE', 'PORTFOLIO_REFRESH']::text[] THEN
    RAISE EXCEPTION 'unsupported job type';
  END IF;

  SELECT *
  INTO claimed
  FROM workos_control.job_envelopes job
  WHERE job.job_type = ANY(p_job_types)
    AND job.due_at <= now()
    AND (
      job.claim_state = 'PENDING'
      OR (job.claim_state = 'CLAIMED' AND job.lease_expires_at <= now())
    )
  ORDER BY job.due_at, job.created_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  UPDATE workos_control.job_envelopes
  SET claim_state = 'CLAIMED',
      claim_token = gen_random_uuid(),
      claimed_by = p_worker_id,
      lease_expires_at = now() + make_interval(secs => p_lease_seconds),
      attempt_count = attempt_count + 1,
      updated_at = now()
  WHERE id = claimed.id
  RETURNING * INTO claimed;

  INSERT INTO workos.job_claim_events (
    tenant_id, workspace_id, job_id, job_type, resource_id,
    transition, worker_id, claim_token_hash
  )
  VALUES (
    claimed.tenant_id, claimed.workspace_id, claimed.id, claimed.job_type,
    claimed.resource_id, 'CLAIMED', p_worker_id,
    encode(digest(claimed.claim_token::text, 'sha256'), 'hex')
  );

  RETURN QUERY SELECT
    claimed.id, claimed.tenant_id, claimed.workspace_id, claimed.job_type,
    claimed.resource_id, claimed.due_at, claimed.claim_token;
END
$$;

CREATE OR REPLACE FUNCTION workos_control.finish_claimed_job(
  p_job_id uuid,
  p_claim_token uuid,
  p_final_state workos.job_state
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, workos_control, workos
AS $$
DECLARE
  finished workos_control.job_envelopes%ROWTYPE;
BEGIN
  IF p_final_state NOT IN ('COMPLETED', 'FAILED') THEN
    RAISE EXCEPTION 'invalid final job state';
  END IF;

  UPDATE workos_control.job_envelopes
  SET claim_state = p_final_state,
      lease_expires_at = NULL,
      updated_at = now()
  WHERE id = p_job_id
    AND claim_token = p_claim_token
    AND claim_state = 'CLAIMED'
    AND lease_expires_at > now()
  RETURNING * INTO finished;

  IF NOT FOUND THEN
    RETURN false;
  END IF;

  INSERT INTO workos.job_claim_events (
    tenant_id, workspace_id, job_id, job_type, resource_id,
    transition, worker_id, claim_token_hash
  )
  VALUES (
    finished.tenant_id, finished.workspace_id, finished.id, finished.job_type,
    finished.resource_id, p_final_state::text, finished.claimed_by,
    encode(digest(p_claim_token::text, 'sha256'), 'hex')
  );

  RETURN true;
END
$$;

CREATE OR REPLACE FUNCTION workos_security.prevent_job_envelope_scope_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id
    OR NEW.workspace_id <> OLD.workspace_id
    OR NEW.job_type <> OLD.job_type
    OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
    OR NEW.due_at <> OLD.due_at
    OR NEW.dedupe_key <> OLD.dedupe_key THEN
    RAISE EXCEPTION 'job envelope scope is immutable';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER job_envelope_scope_immutable
BEFORE UPDATE ON workos_control.job_envelopes
FOR EACH ROW EXECUTE FUNCTION workos_security.prevent_job_envelope_scope_change();

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'workspace_memberships', 'principals', 'principal_user_links',
    'operator_assignments', 'operator_assignment_principals',
    'operator_assignment_action_scopes', 'operator_assignment_data_scopes',
    'portfolio_metadata_projection', 'work_objects', 'tasks',
    'task_executor_assignments', 'commitments', 'activity_events',
    'audit_records', 'work_state_transitions', 'outbox_messages',
    'effect_instances', 'execution_guards', 'job_claim_events'
  ]
  LOOP
    EXECUTE format('ALTER TABLE workos.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE workos.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'CREATE POLICY normal_context_policy ON workos.%I USING (workos_security.active_context_allows(tenant_id, workspace_id)) WITH CHECK (workos_security.active_context_allows(tenant_id, workspace_id))',
      table_name
    );
  END LOOP;
END
$$;

ALTER TABLE workos.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE workos.workspaces FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_normal_context_policy ON workos.workspaces
  USING (workos_security.active_context_allows(tenant_id, id))
  WITH CHECK (workos_security.active_context_allows(tenant_id, id));

ALTER TABLE workos.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE workos.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_normal_context_policy ON workos.tenants
  USING (
    current_setting('workos.access_mode', true) = 'NORMAL'
    AND id = workos_security.setting_uuid('workos.tenant_id')
    AND workos_security.active_context_allows(
      id,
      workos_security.setting_uuid('workos.workspace_id')
    )
  );

ALTER TABLE workos.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE workos.users FORCE ROW LEVEL SECURITY;
CREATE POLICY user_self_policy ON workos.users
  USING (
    current_setting('workos.access_mode', true) = 'NORMAL'
    AND id = workos_security.setting_uuid('workos.user_id')
  );

ALTER TABLE workos.external_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE workos.external_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY external_identity_self_policy ON workos.external_identities
  USING (
    current_setting('workos.access_mode', true) = 'NORMAL'
    AND user_id = workos_security.setting_uuid('workos.user_id')
  );

ALTER TABLE workos.portfolio_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE workos.portfolio_contexts FORCE ROW LEVEL SECURITY;
CREATE POLICY portfolio_context_self_policy ON workos.portfolio_contexts
  USING (
    current_setting('workos.access_mode', true) = 'ACCESS_CATALOG'
    AND user_id = workos_security.setting_uuid('workos.user_id')
  )
  WITH CHECK (
    current_setting('workos.access_mode', true) = 'ACCESS_CATALOG'
    AND user_id = workos_security.setting_uuid('workos.user_id')
  );

ALTER TABLE workos.portfolio_context_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE workos.portfolio_context_assignments FORCE ROW LEVEL SECURITY;

CREATE POLICY task_system_job_policy ON workos.tasks
  TO workos_worker
  USING (workos_security.system_job_allows(tenant_id, workspace_id, id, 'TASK_RECONCILE'))
  WITH CHECK (workos_security.system_job_allows(tenant_id, workspace_id, id, 'TASK_RECONCILE'));

CREATE POLICY work_object_system_job_policy ON workos.work_objects
  TO workos_worker
  USING (workos_security.system_job_allows(tenant_id, workspace_id, id, 'WORK_RECONCILE'))
  WITH CHECK (workos_security.system_job_allows(tenant_id, workspace_id, id, 'WORK_RECONCILE'));

CREATE POLICY outbox_system_job_policy ON workos.outbox_messages
  FOR SELECT TO workos_worker
  USING (workos_security.system_job_allows(tenant_id, workspace_id, id, 'OUTBOX_DELIVERY'));

REVOKE ALL ON ALL TABLES IN SCHEMA workos FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA workos_control FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA workos_security FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA workos_control FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE ON
  workos.workspaces,
  workos.workspace_memberships,
  workos.principals,
  workos.principal_user_links,
  workos.operator_assignments,
  workos.operator_assignment_principals,
  workos.operator_assignment_action_scopes,
  workos.operator_assignment_data_scopes,
  workos.portfolio_metadata_projection,
  workos.work_objects,
  workos.tasks,
  workos.task_executor_assignments,
  workos.commitments,
  workos.execution_guards
TO workos_runtime;

GRANT SELECT ON workos.tenants, workos.users, workos.external_identities TO workos_runtime;
GRANT SELECT, INSERT ON
  workos.activity_events,
  workos.audit_records,
  workos.work_state_transitions,
  workos.outbox_messages,
  workos.effect_instances,
  workos.job_claim_events
TO workos_runtime;

GRANT SELECT, INSERT ON workos.portfolio_contexts, workos.portfolio_context_assignments TO workos_runtime;

GRANT SELECT, UPDATE ON workos.tasks, workos.work_objects, workos.execution_guards TO workos_worker;
GRANT SELECT ON workos.outbox_messages TO workos_worker;
GRANT INSERT ON
  workos.activity_events,
  workos.audit_records,
  workos.work_state_transitions,
  workos.job_claim_events
TO workos_worker;

REVOKE ALL ON workos_control.job_envelopes FROM workos_runtime, workos_worker;

GRANT EXECUTE ON FUNCTION workos_security.get_access_catalog_for_current_user() TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_security.open_portfolio_context(text) TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_security.get_portfolio_metadata(uuid) TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_security.setting_uuid(text) TO workos_runtime, workos_worker;
GRANT EXECUTE ON FUNCTION workos_security.active_context_allows(uuid, uuid) TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_security.system_job_allows(uuid, uuid, uuid, text) TO workos_worker;
GRANT EXECUTE ON FUNCTION workos_control.enqueue_job(text, uuid, timestamptz, text) TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_control.claim_due_job(text, text[], integer) TO workos_worker;
GRANT EXECUTE ON FUNCTION workos_control.finish_claimed_job(uuid, uuid, workos.job_state) TO workos_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE workos_schema_owner IN SCHEMA workos REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE workos_schema_owner IN SCHEMA workos_control REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE workos_schema_owner IN SCHEMA workos_security REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE workos_schema_owner IN SCHEMA workos_control REVOKE ALL ON FUNCTIONS FROM PUBLIC;

COMMIT;