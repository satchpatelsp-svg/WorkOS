import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import type { PoolClient } from "pg";
import type {
  AccessCatalogContext,
  NormalRequestContext,
} from "@workspace/request-context";
import { runtimePool } from "./pool";
import { verifyRuntimeDatabaseIdentity } from "./pool";
import * as schema from "./schema";

export type ScopedDatabase = NodePgDatabase<typeof schema>;

async function setLocal(client: PoolClient, name: string, value: string): Promise<void> {
  await client.query("select set_config($1, $2, true)", [name, value]);
}

async function runScoped<T>(
  configure: (client: PoolClient) => Promise<void>,
  operation: (db: ScopedDatabase, client: PoolClient) => Promise<T>,
): Promise<T> {
  await verifyRuntimeDatabaseIdentity();
  const client = await runtimePool.connect();
  try {
    await client.query("begin");
    await configure(client);
    const scopedDb = drizzle(client, { schema });
    const result = await operation(scopedDb, client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

export function withNormalContext<T>(
  context: NormalRequestContext,
  operation: (db: ScopedDatabase, client: PoolClient) => Promise<T>,
): Promise<T> {
  return runScoped(
    async (client) => {
      await setLocal(client, "workos.access_mode", "NORMAL");
      await setLocal(client, "workos.user_id", context.userId);
      await setLocal(client, "workos.tenant_id", context.tenantId);
      await setLocal(client, "workos.workspace_id", context.workspaceId);
      await setLocal(client, "workos.context_version", String(context.membershipContextVersion));
      if (context.assignmentId) {
        await setLocal(client, "workos.assignment_id", context.assignmentId);
        await setLocal(
          client,
          "workos.assignment_context_version",
          String(context.assignmentContextVersion),
        );
      }
      if (context.representedPrincipalId) {
        await setLocal(client, "workos.principal_id", context.representedPrincipalId);
      }
    },
    operation,
  );
}

export function withAccessCatalogContext<T>(
  context: AccessCatalogContext,
  operation: (db: ScopedDatabase, client: PoolClient) => Promise<T>,
): Promise<T> {
  return runScoped(
    async (client) => {
      await setLocal(client, "workos.access_mode", "ACCESS_CATALOG");
      await setLocal(client, "workos.user_id", context.userId);
    },
    operation,
  );
}