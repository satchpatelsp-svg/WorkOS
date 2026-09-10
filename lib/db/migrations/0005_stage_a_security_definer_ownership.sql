BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workos_security_definer') THEN
    CREATE ROLE workos_security_definer
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA workos, workos_security, workos_control TO workos_security_definer;

GRANT SELECT ON
  workos.tenants,
  workos.workspaces,
  workos.users,
  workos.workspace_memberships,
  workos.principals,
  workos.operator_assignments,
  workos.operator_assignment_principals,
  workos.portfolio_contexts,
  workos.portfolio_context_assignments,
  workos.portfolio_metadata_projection
TO workos_security_definer;

GRANT SELECT, INSERT ON
  workos.portfolio_contexts,
  workos.portfolio_context_assignments
TO workos_security_definer;

GRANT SELECT, INSERT, UPDATE ON workos_control.job_envelopes TO workos_security_definer;
GRANT INSERT ON workos.job_claim_events TO workos_security_definer;

-- PostgreSQL requires the target owner to have CREATE on the containing
-- schema while ownership is transferred. This is temporary migration
-- authority and is revoked immediately after the transfers.
GRANT CREATE ON SCHEMA workos_security, workos_control TO workos_security_definer;

ALTER FUNCTION workos_security.active_context_allows(uuid, uuid)
  OWNER TO workos_security_definer;
ALTER FUNCTION workos_security.system_job_allows(uuid, uuid, uuid, text)
  OWNER TO workos_security_definer;
ALTER FUNCTION workos_security.get_access_catalog_for_current_user()
  OWNER TO workos_security_definer;
ALTER FUNCTION workos_security.open_portfolio_context(text)
  OWNER TO workos_security_definer;
ALTER FUNCTION workos_security.get_portfolio_metadata(uuid)
  OWNER TO workos_security_definer;
ALTER FUNCTION workos_control.enqueue_job(text, uuid, timestamptz, text)
  OWNER TO workos_security_definer;
ALTER FUNCTION workos_control.claim_due_job(text, text[], integer)
  OWNER TO workos_security_definer;
ALTER FUNCTION workos_control.finish_claimed_job(uuid, uuid, workos.job_state)
  OWNER TO workos_security_definer;
ALTER FUNCTION workos_security.prevent_job_envelope_scope_change()
  OWNER TO workos_security_definer;

REVOKE CREATE ON SCHEMA workos_security, workos_control FROM workos_security_definer;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA workos_security FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA workos_control FROM PUBLIC;

GRANT EXECUTE ON FUNCTION workos_security.get_access_catalog_for_current_user()
  TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_security.open_portfolio_context(text)
  TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_security.get_portfolio_metadata(uuid)
  TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_security.setting_uuid(text)
  TO workos_runtime, workos_worker, workos_security_definer;
GRANT EXECUTE ON FUNCTION workos_security.active_context_allows(uuid, uuid)
  TO workos_runtime, workos_security_definer;
GRANT EXECUTE ON FUNCTION workos_security.system_job_allows(uuid, uuid, uuid, text)
  TO workos_worker, workos_security_definer;
GRANT EXECUTE ON FUNCTION workos_control.enqueue_job(text, uuid, timestamptz, text)
  TO workos_runtime;
GRANT EXECUTE ON FUNCTION workos_control.claim_due_job(text, text[], integer)
  TO workos_worker;
GRANT EXECUTE ON FUNCTION workos_control.finish_claimed_job(uuid, uuid, workos.job_state)
  TO workos_worker;

COMMIT;