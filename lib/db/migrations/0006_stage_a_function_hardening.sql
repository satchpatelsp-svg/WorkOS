BEGIN;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO workos_security_definer;

ALTER FUNCTION workos_security.open_portfolio_context(text)
  SET search_path = pg_catalog, workos, public;
ALTER FUNCTION workos_control.claim_due_job(text, text[], integer)
  SET search_path = pg_catalog, workos_control, workos, public;
ALTER FUNCTION workos_control.finish_claimed_job(uuid, uuid, workos.job_state)
  SET search_path = pg_catalog, workos_control, workos, public;

GRANT EXECUTE ON FUNCTION workos_security.setting_uuid(text)
  TO workos_runtime, workos_worker, workos_security_definer;
GRANT EXECUTE ON FUNCTION workos_security.active_context_allows(uuid, uuid)
  TO workos_runtime, workos_security_definer;
GRANT EXECUTE ON FUNCTION workos_security.system_job_allows(uuid, uuid, uuid, text)
  TO workos_worker, workos_security_definer;

COMMIT;