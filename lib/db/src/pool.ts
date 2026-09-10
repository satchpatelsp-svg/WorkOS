import {
  assertLeastPrivilegeLogin,
  createRequiredPool,
  requireDatabaseUrl,
} from "./required-connection";

export function assertRuntimeDatabaseConfigured(): void {
  requireDatabaseUrl("DATABASE_RUNTIME_URL");
}

export const runtimePool = createRequiredPool(
  "DATABASE_RUNTIME_URL",
  "work-os-api",
);

let verifiedIdentity: Promise<void> | undefined;

export function verifyRuntimeDatabaseIdentity(): Promise<void> {
  verifiedIdentity ??= (async () => {
    const client = await runtimePool.connect();
    try {
      await assertLeastPrivilegeLogin(client, "workos_runtime");
    } finally {
      client.release();
    }
  })();
  return verifiedIdentity;
}