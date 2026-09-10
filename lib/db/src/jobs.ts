import type { SystemJobContext } from "@workspace/request-context";
import { verifyWorkerDatabaseIdentity, workerPool } from "./worker-pool";
import { withSystemJobContext } from "./worker-context";

export const stageAJobTypes = [
  "OUTBOX_DELIVERY",
  "WORK_RECONCILE",
  "TASK_RECONCILE",
  "PORTFOLIO_REFRESH",
] as const;

export type StageAJobType = (typeof stageAJobTypes)[number];

export interface ClaimedJob {
  jobId: string;
  tenantId: string;
  workspaceId: string;
  jobType: StageAJobType;
  resourceId: string | null;
  dueAt: Date;
  claimToken: string;
}

export async function claimDueJob(
  workerId: string,
  jobTypes: readonly StageAJobType[],
  leaseSeconds = 60,
): Promise<ClaimedJob | null> {
  await verifyWorkerDatabaseIdentity();
  const client = await workerPool.connect();
  try {
    await client.query("begin");
    const result = await client.query<{
      job_id: string;
      tenant_id: string;
      workspace_id: string;
      job_type: StageAJobType;
      resource_id: string | null;
      due_at: Date;
      claim_token: string;
    }>("select * from workos_control.claim_due_job($1, $2::text[], $3)", [
      workerId,
      [...jobTypes],
      leaseSeconds,
    ]);
    await client.query("commit");
    const row = result.rows[0];
    return row
      ? {
          jobId: row.job_id,
          tenantId: row.tenant_id,
          workspaceId: row.workspace_id,
          jobType: row.job_type,
          resourceId: row.resource_id,
          dueAt: row.due_at,
          claimToken: row.claim_token,
        }
      : null;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

export async function finishClaimedJob(
  context: SystemJobContext,
  finalState: "COMPLETED" | "FAILED",
): Promise<boolean> {
  return withSystemJobContext(context, async (_db, client) => {
    const result = await client.query<{ finished: boolean }>(
      "select workos_control.finish_claimed_job($1, $2, $3::workos.job_state) as finished",
      [context.systemJobId, context.claimToken, finalState],
    );
    return result.rows[0]?.finished ?? false;
  });
}