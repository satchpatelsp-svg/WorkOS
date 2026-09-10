BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workos_schema_owner') THEN
    CREATE ROLE workos_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workos_migrator') THEN
    CREATE ROLE workos_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workos_runtime') THEN
    CREATE ROLE workos_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workos_worker') THEN
    CREATE ROLE workos_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workos_security_definer') THEN
    CREATE ROLE workos_security_definer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
  END IF;

  EXECUTE format(
    'GRANT workos_schema_owner, workos_security_definer TO %I',
    current_user
  );
  EXECUTE format(
    'REVOKE workos_runtime, workos_worker, workos_migrator FROM %I',
    current_user
  );

  IF NOT EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = 'workos_runtime'
      AND rolcanlogin
      AND NOT rolsuper
      AND NOT rolbypassrls
      AND NOT rolcreaterole
      AND NOT rolcreatedb
      AND NOT rolreplication
      AND NOT rolinherit
  ) THEN
    RAISE EXCEPTION
      'workos_runtime must already be an approved external LOGIN role; migration 0001 will not alter its credentials';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = 'workos_worker'
      AND rolcanlogin
      AND NOT rolsuper
      AND NOT rolbypassrls
      AND NOT rolcreaterole
      AND NOT rolcreatedb
      AND NOT rolreplication
      AND NOT rolinherit
  ) THEN
    RAISE EXCEPTION
      'workos_worker must already be an approved external LOGIN role; migration 0001 will not alter its credentials';
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS workos AUTHORIZATION workos_schema_owner;
CREATE SCHEMA IF NOT EXISTS workos_security AUTHORIZATION workos_schema_owner;
CREATE SCHEMA IF NOT EXISTS workos_control AUTHORIZATION workos_schema_owner;

REVOKE ALL ON SCHEMA workos FROM PUBLIC;
REVOKE ALL ON SCHEMA workos_security FROM PUBLIC;
REVOKE ALL ON SCHEMA workos_control FROM PUBLIC;

GRANT USAGE ON SCHEMA workos TO workos_runtime, workos_worker;
GRANT USAGE ON SCHEMA workos_security TO workos_runtime, workos_worker;
GRANT USAGE ON SCHEMA workos_control TO workos_runtime, workos_worker;
GRANT USAGE ON SCHEMA workos, workos_security, workos_control TO workos_security_definer;

GRANT workos_schema_owner TO workos_migrator;

COMMIT;