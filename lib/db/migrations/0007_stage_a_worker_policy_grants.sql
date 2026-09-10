BEGIN;

-- PostgreSQL validates every function referenced by an applicable permissive
-- policy. The worker therefore needs EXECUTE on the normal-context helper even
-- though SYSTEM_JOB requests can never satisfy the NORMAL branch.
GRANT EXECUTE ON FUNCTION workos_security.active_context_allows(uuid, uuid)
  TO workos_worker;

COMMIT;