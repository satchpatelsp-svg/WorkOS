import {
  claimDueJob,
  finishClaimedJob,
  verifyWorkerDatabaseIdentity,
  withSystemJobContext,
  type StageAJobType,
} from "@workspace/db/worker";

export interface WorkerDependencies {
  workerId: string;
  supportedJobTypes: readonly StageAJobType[];
}

export async function processOneStageAJob({
  workerId,
  supportedJobTypes,
}: WorkerDependencies): Promise<boolean> {
  await verifyWorkerDatabaseIdentity();
  const job = await claimDueJob(workerId, supportedJobTypes);
  if (!job) {
    return false;
  }

  const context = {
    mode: "SYSTEM_JOB" as const,
    systemJobId: job.jobId,
    claimToken: job.claimToken,
    tenantId: job.tenantId,
    workspaceId: job.workspaceId,
    resourceId: job.resourceId ?? undefined,
    jobType: job.jobType,
  };

  try {
    await withSystemJobContext(context, async () => {
      // Stage A deliberately contains no connector or consequence execution.
      // A later stage registers handlers by the already-validated job type.
    });
    await finishClaimedJob(context, "COMPLETED");
    return true;
  } catch (error) {
    await finishClaimedJob(context, "FAILED");
    throw error;
  }
}