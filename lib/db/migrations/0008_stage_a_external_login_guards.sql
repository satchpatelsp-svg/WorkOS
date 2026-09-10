BEGIN;

DO $$
BEGIN
  IF current_user IN ('workos_runtime', 'workos_worker') THEN
    RAISE EXCEPTION 'migrations must not run through an application login';
  END IF;
END
$$;

DO $$
DECLARE
  role_name text;
  attributes record;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['workos_runtime', 'workos_worker']
  LOOP
    SELECT
      rolcanlogin,
      rolsuper,
      rolbypassrls,
      rolcreaterole,
      rolcreatedb,
      rolreplication,
      rolinherit
    INTO STRICT attributes
    FROM pg_roles
    WHERE rolname = role_name;

    IF NOT attributes.rolcanlogin THEN
      RAISE EXCEPTION '% must be provisioned as an external LOGIN role before migrations run', role_name;
    END IF;

    IF attributes.rolsuper
      OR attributes.rolbypassrls
      OR attributes.rolcreaterole
      OR attributes.rolcreatedb
      OR attributes.rolreplication
      OR attributes.rolinherit THEN
      RAISE EXCEPTION
        '% has invalid external-login attributes; expected LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION NOINHERIT',
        role_name;
    END IF;

    IF pg_has_role(role_name, 'workos_schema_owner', 'MEMBER')
      OR pg_has_role(role_name, 'workos_security_definer', 'MEMBER')
      OR pg_has_role(role_name, 'workos_migrator', 'MEMBER')
      OR pg_has_role(role_name, current_user, 'MEMBER') THEN
      RAISE EXCEPTION '% can assume a privileged database identity', role_name;
    END IF;

    IF EXISTS (
      SELECT 1
      FROM pg_namespace
      JOIN pg_roles owner_role ON owner_role.oid = pg_namespace.nspowner
      WHERE owner_role.rolname = role_name
        AND pg_namespace.nspname IN ('workos', 'workos_security', 'workos_control')
    ) OR EXISTS (
      SELECT 1
      FROM pg_class
      JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
      JOIN pg_roles owner_role ON owner_role.oid = pg_class.relowner
      WHERE owner_role.rolname = role_name
        AND pg_namespace.nspname IN ('workos', 'workos_security', 'workos_control')
    ) THEN
      RAISE EXCEPTION '% owns Work OS database objects', role_name;
    END IF;
  END LOOP;

  IF pg_has_role('workos_runtime', 'workos_worker', 'MEMBER')
    OR pg_has_role('workos_worker', 'workos_runtime', 'MEMBER') THEN
    RAISE EXCEPTION 'runtime and worker roles must not be members of each other';
  END IF;
END
$$;

COMMIT;