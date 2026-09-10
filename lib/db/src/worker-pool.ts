import {
  assertLeastPrivilegeLogin,
  createRequiredPool,
  requireDatabaseUrl,
} from "./required-connection";

export function assertWorkerDatabaseConfigured(): void {
  requireDatabaseUrl("DATABASE_WORKER_URL");
}

export const workerPool = createRequiredPool(
  "DATABASE_WORKER_URL",
  "work-os-worker",
);

let verifiedIdentity: Promise<void> | undefined;

export function verifyWorkerDatabaseIdentity(): Promise<void> {
  verifiedIdentity ??= (async () => {
    const client = await workerPool.connect();
    try {
      await assertLeastPrivilegeLogin(client, "workos_worker");
    } finally {
      client.release();
    }
  })();
  return verifiedIdentity;
}