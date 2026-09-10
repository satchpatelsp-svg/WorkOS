import { drizzle } from "drizzle-orm/node-postgres";
import type { PoolClient } from "pg";
import type { SystemJobContext } from "@workspace/request-context";
import { workerPool } from "./worker-pool";
import { verifyWorkerDatabaseIdentity } from "./worker-pool";
import type { ScopedDatabase } from "./context";
import * as schema from "./schema";

async function setLocal(
  client: PoolClient,
  name: string,
  value: string,
): Promise<void> {
  await client.query("select set_config($1, $2, true)", [name, value]);
}

export async function withSystemJobContext<T>(
  context: SystemJobContext,
  operation: (db: ScopedDatabase, client: PoolClient) => Promise<T>,
): Promise<T> {
  await verifyWorkerDatabaseIdentity();
  const client = await workerPool.connect();
  try {
    await client.query("begin");
    await setLocal(client, "workos.access_mode", "SYSTEM_JOB");
    await setLocal(client, "workos.system_job_id", context.systemJobId);
    await setLocal(client, "workos.claim_token", context.claimToken);
    await setLocal(client, "workos.tenant_id", context.tenantId);
    await setLocal(client, "workos.workspace_id", context.workspaceId);
    await setLocal(client, "workos.job_type", context.jobType);
    if (context.resourceId) {
      await setLocal(client, "workos.resource_id", context.resourceId);
    }
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