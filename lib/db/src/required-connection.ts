import pg from "pg";
import type { PoolClient } from "pg";

const { Pool } = pg;

type DatabaseSecretName =
  | "DATABASE_RUNTIME_URL"
  | "DATABASE_WORKER_URL";

export function requireDatabaseUrl(name: DatabaseSecretName): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} must be set. Work OS does not fall back to DATABASE_URL.`,
    );
  }
  return value;
}

export function createRequiredPool(
  name: DatabaseSecretName,
  applicationName: string,
): pg.Pool {
  return new Pool({
    connectionString: requireDatabaseUrl(name),
    application_name: applicationName,
  });
}

export async function assertLeastPrivilegeLogin(
  client: PoolClient,
  expectedRole: "workos_runtime" | "workos_worker",
): Promise<void> {
  const result = await client.query<{
    session_user: string;
    current_user: string;
    rolsuper: boolean;
    rolbypassrls: boolean;
    rolcreaterole: boolean;
    owns_workos_objects: boolean;
    can_assume_schema_owner: boolean;
    can_assume_security_definer: boolean;
    can_assume_migrator: boolean;
  }>(`
    select
      session_user,
      current_user,
      role.rolsuper,
      role.rolbypassrls,
      role.rolcreaterole,
      exists (
        select 1
        from pg_class object
        join pg_namespace namespace on namespace.oid = object.relnamespace
        where object.relowner = role.oid
          and namespace.nspname in ('workos', 'workos_control', 'workos_security')
      ) as owns_workos_objects,
      pg_has_role(current_user, 'workos_schema_owner', 'MEMBER')
        as can_assume_schema_owner,
      pg_has_role(current_user, 'workos_security_definer', 'MEMBER')
        as can_assume_security_definer,
      pg_has_role(current_user, 'workos_migrator', 'MEMBER')
        as can_assume_migrator
    from pg_roles role
    where role.rolname = current_user
  `);

  const identity = result.rows[0];
  if (
    !identity ||
    identity.session_user !== expectedRole ||
    identity.current_user !== expectedRole ||
    identity.rolsuper ||
    identity.rolbypassrls ||
    identity.rolcreaterole ||
    identity.owns_workos_objects ||
    identity.can_assume_schema_owner ||
    identity.can_assume_security_definer ||
    identity.can_assume_migrator
  ) {
    throw new Error(
      `Database connection must be the isolated ${expectedRole} login`,
    );
  }
}