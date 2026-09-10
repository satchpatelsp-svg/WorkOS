BEGIN;

SET LOCAL ROLE workos_schema_owner;

CREATE TYPE workos.record_status AS ENUM ('ACTIVE', 'INACTIVE', 'SUSPENDED', 'REVOKED');
CREATE TYPE workos.principal_type AS ENUM ('PERSON', 'ORGANISATION', 'LEGAL_ENTITY');
CREATE TYPE workos.membership_role AS ENUM ('MEMBER', 'OPERATOR', 'PRINCIPAL', 'WORKSPACE_ADMIN');
CREATE TYPE workos.work_state AS ENUM (
  'PROPOSED', 'OPEN', 'IN_PROGRESS', 'WAITING', 'AWAITING_APPROVAL',
  'BLOCKED', 'HELD', 'EXECUTING', 'VERIFYING', 'COMPLETED', 'FAILED',
  'SUPERSEDED', 'CANCELLED'
);
CREATE TYPE workos.work_object_state AS ENUM ('ACTIVE', 'PAUSED', 'COMPLETED', 'ARCHIVED');
CREATE TYPE workos.actor_type AS ENUM ('USER', 'OPERATOR_ASSIGNMENT', 'SYSTEM_JOB', 'SERVICE');
CREATE TYPE workos.executor_type AS ENUM ('USER', 'OPERATOR_ASSIGNMENT', 'SERVICE');
CREATE TYPE workos.attention_priority AS ENUM ('LOW', 'NORMAL', 'HIGH', 'CRITICAL');
CREATE TYPE workos.job_state AS ENUM ('PENDING', 'CLAIMED', 'COMPLETED', 'FAILED', 'CANCELLED');
CREATE TYPE workos.effect_state AS ENUM ('PENDING', 'RESERVED', 'IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'UNKNOWN', 'REQUIRES_RECONCILIATION');

CREATE TABLE workos.tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  status workos.record_status NOT NULL DEFAULT 'ACTIVE',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id)
);

CREATE TABLE workos.workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES workos.tenants(id),
  name text NOT NULL,
  workspace_type text NOT NULL,
  security_domain text NOT NULL,
  status workos.record_status NOT NULL DEFAULT 'ACTIVE',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, security_domain)
);

CREATE TABLE workos.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name text NOT NULL,
  locale text NOT NULL DEFAULT 'en-GB',
  timezone text NOT NULL DEFAULT 'Europe/London',
  status workos.record_status NOT NULL DEFAULT 'ACTIVE',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workos.external_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES workos.users(id),
  provider text NOT NULL,
  provider_tenant_id text NOT NULL,
  provider_subject_id text NOT NULL,
  email text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  verified_at timestamptz,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_tenant_id, provider_subject_id)
);

CREATE TABLE workos.workspace_memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES workos.users(id),
  role workos.membership_role NOT NULL,
  status workos.record_status NOT NULL DEFAULT 'ACTIVE',
  effective_from timestamptz NOT NULL DEFAULT now(),
  effective_to timestamptz,
  context_version bigint NOT NULL DEFAULT 1 CHECK (context_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, user_id),
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);

CREATE TABLE workos.principals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  principal_type workos.principal_type NOT NULL,
  display_name text NOT NULL,
  status workos.record_status NOT NULL DEFAULT 'ACTIVE',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  UNIQUE (tenant_id, workspace_id, id)
);

CREATE TABLE workos.principal_user_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES workos.users(id),
  relationship_type text NOT NULL DEFAULT 'REPRESENTS_SELF',
  effective_from timestamptz NOT NULL DEFAULT now(),
  effective_to timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id, principal_id) REFERENCES workos.principals(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, user_id) REFERENCES workos.workspace_memberships(tenant_id, workspace_id, user_id),
  UNIQUE (tenant_id, workspace_id, principal_id, user_id, relationship_type),
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);

CREATE TABLE workos.operator_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  operator_user_id uuid NOT NULL,
  service_profile text NOT NULL,
  status workos.record_status NOT NULL DEFAULT 'ACTIVE',
  effective_from timestamptz NOT NULL DEFAULT now(),
  effective_to timestamptz,
  context_version bigint NOT NULL DEFAULT 1 CHECK (context_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, operator_user_id) REFERENCES workos.workspace_memberships(tenant_id, workspace_id, user_id),
  UNIQUE (tenant_id, workspace_id, id),
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);

CREATE TABLE workos.operator_assignment_principals (
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  assignment_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, workspace_id, assignment_id, principal_id),
  FOREIGN KEY (tenant_id, workspace_id, assignment_id) REFERENCES workos.operator_assignments(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, principal_id) REFERENCES workos.principals(tenant_id, workspace_id, id)
);

CREATE TABLE workos.operator_assignment_action_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  assignment_id uuid NOT NULL,
  action_class text NOT NULL,
  authority_mode text NOT NULL,
  effective_from timestamptz NOT NULL DEFAULT now(),
  effective_to timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id, assignment_id) REFERENCES workos.operator_assignments(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, assignment_id, action_class),
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);

CREATE TABLE workos.operator_assignment_data_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  assignment_id uuid NOT NULL,
  scope_type text NOT NULL,
  scope_key text NOT NULL,
  effective_from timestamptz NOT NULL DEFAULT now(),
  effective_to timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id, assignment_id) REFERENCES workos.operator_assignments(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, assignment_id, scope_type, scope_key),
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);

CREATE TABLE workos.portfolio_contexts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES workos.users(id),
  purpose text NOT NULL,
  snapshot_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > created_at)
);

CREATE TABLE workos.portfolio_context_assignments (
  portfolio_context_id uuid NOT NULL REFERENCES workos.portfolio_contexts(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  assignment_id uuid NOT NULL,
  PRIMARY KEY (portfolio_context_id, tenant_id, workspace_id, assignment_id),
  FOREIGN KEY (tenant_id, workspace_id, assignment_id) REFERENCES workos.operator_assignments(tenant_id, workspace_id, id)
);

CREATE TABLE workos.portfolio_metadata_projection (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  assignment_id uuid NOT NULL,
  category text NOT NULL,
  urgency workos.attention_priority NOT NULL DEFAULT 'NORMAL',
  age_seconds bigint NOT NULL DEFAULT 0 CHECK (age_seconds >= 0),
  sla_due_at timestamptz,
  status text NOT NULL,
  refreshed_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, assignment_id) REFERENCES workos.operator_assignments(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id)
);

CREATE TABLE workos.work_objects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  work_type text NOT NULL,
  title text NOT NULL,
  status workos.work_object_state NOT NULL DEFAULT 'ACTIVE',
  accountable_principal_id uuid,
  owner_user_id uuid,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, accountable_principal_id) REFERENCES workos.principals(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, owner_user_id) REFERENCES workos.workspace_memberships(tenant_id, workspace_id, user_id),
  UNIQUE (tenant_id, workspace_id, id)
);

CREATE TABLE workos.tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  work_object_id uuid,
  intent text NOT NULL,
  status workos.work_state NOT NULL DEFAULT 'OPEN',
  accountable_owner_user_id uuid,
  next_action_owner_user_id uuid,
  waiting_on_type text,
  waiting_on_key text,
  next_check_at timestamptz,
  due_at timestamptz,
  priority workos.attention_priority NOT NULL DEFAULT 'NORMAL',
  completion_condition jsonb NOT NULL,
  resolution_event_id uuid,
  superseded_by_task_id uuid,
  blocked_reason text,
  held_reason text,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, work_object_id) REFERENCES workos.work_objects(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, accountable_owner_user_id) REFERENCES workos.workspace_memberships(tenant_id, workspace_id, user_id),
  FOREIGN KEY (tenant_id, workspace_id, next_action_owner_user_id) REFERENCES workos.workspace_memberships(tenant_id, workspace_id, user_id),
  FOREIGN KEY (tenant_id, workspace_id, superseded_by_task_id) REFERENCES workos.tasks(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  CHECK (status <> 'WAITING' OR waiting_on_type IS NOT NULL),
  CHECK (status <> 'BLOCKED' OR blocked_reason IS NOT NULL),
  CHECK (status <> 'HELD' OR held_reason IS NOT NULL),
  CHECK (status <> 'SUPERSEDED' OR superseded_by_task_id IS NOT NULL)
);

CREATE TABLE workos.task_executor_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  task_id uuid NOT NULL,
  executor_type workos.executor_type NOT NULL,
  executor_user_id uuid,
  executor_assignment_id uuid,
  executor_service_id text,
  effective_from timestamptz NOT NULL DEFAULT now(),
  effective_to timestamptz,
  is_current boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id, task_id) REFERENCES workos.tasks(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, executor_user_id) REFERENCES workos.workspace_memberships(tenant_id, workspace_id, user_id),
  FOREIGN KEY (tenant_id, workspace_id, executor_assignment_id) REFERENCES workos.operator_assignments(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  CHECK (num_nonnulls(executor_user_id, executor_assignment_id, executor_service_id) = 1),
  CHECK (
    (executor_type = 'USER' AND executor_user_id IS NOT NULL) OR
    (executor_type = 'OPERATOR_ASSIGNMENT' AND executor_assignment_id IS NOT NULL) OR
    (executor_type = 'SERVICE' AND executor_service_id IS NOT NULL)
  ),
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);
CREATE UNIQUE INDEX task_one_current_executor
  ON workos.task_executor_assignments (tenant_id, workspace_id, task_id)
  WHERE is_current;

CREATE TABLE workos.commitments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  work_object_id uuid,
  promisor_principal_id uuid NOT NULL,
  beneficiary_principal_id uuid NOT NULL,
  commitment_text text NOT NULL,
  due_at timestamptz,
  status workos.work_state NOT NULL DEFAULT 'OPEN',
  completion_condition jsonb NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, work_object_id) REFERENCES workos.work_objects(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, promisor_principal_id) REFERENCES workos.principals(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, beneficiary_principal_id) REFERENCES workos.principals(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id)
);

CREATE TABLE workos.activity_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL,
  actor_type workos.actor_type NOT NULL,
  actor_user_id uuid,
  actor_assignment_id uuid,
  actor_system_job_id uuid,
  actor_service_id text,
  represented_principal_id uuid,
  subject_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
  source_snapshot jsonb,
  payload jsonb NOT NULL,
  causation_id uuid,
  correlation_id uuid,
  correction_of_event_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, actor_user_id) REFERENCES workos.workspace_memberships(tenant_id, workspace_id, user_id),
  FOREIGN KEY (tenant_id, workspace_id, actor_assignment_id) REFERENCES workos.operator_assignments(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, represented_principal_id) REFERENCES workos.principals(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, correction_of_event_id) REFERENCES workos.activity_events(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  CHECK (num_nonnulls(actor_user_id, actor_assignment_id, actor_system_job_id, actor_service_id) = 1)
);

ALTER TABLE workos.tasks
  ADD CONSTRAINT tasks_resolution_event_fk
  FOREIGN KEY (tenant_id, workspace_id, resolution_event_id)
  REFERENCES workos.activity_events(tenant_id, workspace_id, id);

CREATE TABLE workos.audit_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  actor_type workos.actor_type NOT NULL,
  actor_snapshot jsonb NOT NULL,
  represented_principal_id uuid,
  operation text NOT NULL,
  resource_type text NOT NULL,
  resource_id uuid,
  before_version bigint,
  after_version bigint,
  request_id text NOT NULL,
  correlation_id uuid,
  result text NOT NULL,
  reason_code text,
  safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  correction_of_record_id uuid,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, represented_principal_id) REFERENCES workos.principals(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, correction_of_record_id) REFERENCES workos.audit_records(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id)
);

CREATE TABLE workos.work_state_transitions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  entity_type text NOT NULL CHECK (entity_type IN ('WORK_OBJECT', 'TASK', 'COMMITMENT')),
  entity_id uuid NOT NULL,
  from_state text,
  to_state text NOT NULL,
  actor_snapshot jsonb NOT NULL,
  reason text,
  event_id uuid,
  correction_of_transition_id uuid,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, event_id) REFERENCES workos.activity_events(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, correction_of_transition_id) REFERENCES workos.work_state_transitions(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id)
);

CREATE TABLE workos.outbox_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  event_id uuid,
  job_type text NOT NULL,
  resource_id uuid,
  payload jsonb NOT NULL,
  available_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, event_id) REFERENCES workos.activity_events(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id)
);

CREATE TABLE workos.effect_instances (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  task_id uuid,
  commitment_id uuid,
  transition_code text NOT NULL,
  occurrence_id text NOT NULL,
  effect_fingerprint text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id, task_id) REFERENCES workos.tasks(tenant_id, workspace_id, id),
  FOREIGN KEY (tenant_id, workspace_id, commitment_id) REFERENCES workos.commitments(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, effect_fingerprint),
  CHECK (num_nonnulls(task_id, commitment_id) = 1),
  CHECK (length(occurrence_id) >= 8)
);

CREATE TABLE workos.execution_guards (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  effect_instance_id uuid NOT NULL,
  idempotency_key text NOT NULL,
  status workos.effect_state NOT NULL DEFAULT 'PENDING',
  provider_idempotency_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id, effect_instance_id) REFERENCES workos.effect_instances(tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, effect_instance_id),
  UNIQUE (tenant_id, workspace_id, idempotency_key)
);

CREATE TABLE workos_control.job_envelopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  job_type text NOT NULL,
  resource_id uuid,
  due_at timestamptz NOT NULL DEFAULT now(),
  claim_state workos.job_state NOT NULL DEFAULT 'PENDING',
  claim_token uuid,
  claimed_by text,
  lease_expires_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  dedupe_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  UNIQUE (tenant_id, workspace_id, id),
  UNIQUE (tenant_id, workspace_id, dedupe_key)
);

CREATE TABLE workos.job_claim_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  job_id uuid NOT NULL,
  job_type text NOT NULL,
  resource_id uuid,
  transition text NOT NULL,
  worker_id text,
  claim_token_hash text,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES workos.workspaces(tenant_id, id),
  UNIQUE (tenant_id, workspace_id, id)
);

ALTER TABLE workos.tenants OWNER TO workos_schema_owner;
ALTER TABLE workos.workspaces OWNER TO workos_schema_owner;
ALTER TABLE workos.users OWNER TO workos_schema_owner;
ALTER TABLE workos.external_identities OWNER TO workos_schema_owner;
ALTER TABLE workos.workspace_memberships OWNER TO workos_schema_owner;
ALTER TABLE workos.principals OWNER TO workos_schema_owner;
ALTER TABLE workos.principal_user_links OWNER TO workos_schema_owner;
ALTER TABLE workos.operator_assignments OWNER TO workos_schema_owner;
ALTER TABLE workos.operator_assignment_principals OWNER TO workos_schema_owner;
ALTER TABLE workos.operator_assignment_action_scopes OWNER TO workos_schema_owner;
ALTER TABLE workos.operator_assignment_data_scopes OWNER TO workos_schema_owner;
ALTER TABLE workos.portfolio_contexts OWNER TO workos_schema_owner;
ALTER TABLE workos.portfolio_context_assignments OWNER TO workos_schema_owner;
ALTER TABLE workos.portfolio_metadata_projection OWNER TO workos_schema_owner;
ALTER TABLE workos.work_objects OWNER TO workos_schema_owner;
ALTER TABLE workos.tasks OWNER TO workos_schema_owner;
ALTER TABLE workos.task_executor_assignments OWNER TO workos_schema_owner;
ALTER TABLE workos.commitments OWNER TO workos_schema_owner;
ALTER TABLE workos.activity_events OWNER TO workos_schema_owner;
ALTER TABLE workos.audit_records OWNER TO workos_schema_owner;
ALTER TABLE workos.work_state_transitions OWNER TO workos_schema_owner;
ALTER TABLE workos.outbox_messages OWNER TO workos_schema_owner;
ALTER TABLE workos.effect_instances OWNER TO workos_schema_owner;
ALTER TABLE workos.execution_guards OWNER TO workos_schema_owner;
ALTER TABLE workos_control.job_envelopes OWNER TO workos_schema_owner;
ALTER TABLE workos.job_claim_events OWNER TO workos_schema_owner;

COMMIT;