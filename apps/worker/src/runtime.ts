import { hostname } from "node:os";

export const MIN_IDLE_BACKOFF_MS = 250;
export const MAX_IDLE_BACKOFF_MS = 5_000;

const IDENTITY_QUERY = `
  select
    session_user,
    current_user,
    role.rolsuper as superuser,
    role.rolbypassrls as bypassrls,
    role.rolcreaterole as createrole,
    role.rolcreatedb as createdb,
    role.rolreplication as replication,
    role.rolinherit as inherit
  from pg_roles as role
  where role.rolname = current_user
`;

const FORBIDDEN_DATABASE_URLS = [
  "DATABASE_RUNTIME_URL",
  "DATABASE_MIGRATION_URL",
] as const;

export interface WorkerClient {
  query<T>(queryText: string): Promise<{ rows: T[] }>;
  release(): void;
}

export interface WorkerPool {
  connect(): Promise<WorkerClient>;
  end(): Promise<void>;
}

export interface WorkerIdentity {
  session_user: string;
  current_user: string;
  superuser: boolean;
  bypassrls: boolean;
  createrole: boolean;
  createdb: boolean;
  replication: boolean;
  inherit: boolean;
}

export interface SignalSource {
  on(signal: "SIGINT" | "SIGTERM", listener: () => void): unknown;
  off(signal: "SIGINT" | "SIGTERM", listener: () => void): unknown;
}

export interface ProcessStageAJob {
  (dependencies: {
    workerId: string;
    supportedJobTypes: readonly string[];
  }): Promise<boolean>;
}

export interface RunWorkerOptions {
  env?: NodeJS.ProcessEnv;
  pool?: WorkerPool;
  processStageAJob?: ProcessStageAJob;
  supportedJobTypes?: readonly string[];
  workerId?: string;
  signals?: SignalSource;
  sleep?: (milliseconds: number) => Promise<void>;
}

export function validateWorkerEnvironment(
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (!env.DATABASE_WORKER_URL) {
    throw new Error("DATABASE_WORKER_URL must be set");
  }

  for (const name of FORBIDDEN_DATABASE_URLS) {
    if (Object.prototype.hasOwnProperty.call(env, name)) {
      throw new Error(`${name} must not be present in the Worker environment`);
    }
  }
}

export async function assertWorkerIdentity(pool: WorkerPool): Promise<void> {
  const client = await pool.connect();
  try {
    const result = await client.query<WorkerIdentity>(IDENTITY_QUERY);
    const identity = result.rows[0];
    if (
      !identity ||
      identity.session_user !== "workos_worker" ||
      identity.current_user !== "workos_worker" ||
      identity.superuser ||
      identity.bypassrls ||
      identity.createrole ||
      identity.createdb ||
      identity.replication ||
      identity.inherit
    ) {
      throw new Error("Worker database identity check failed");
    }
  } finally {
    client.release();
  }
}

function defaultSleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function defaultWorkerId(): string {
  return `workos-stage-a-worker-${hostname()}-${process.pid}`;
}

async function loadWorkerDependencies(
  onPoolCreated: (pool: WorkerPool) => void,
): Promise<{
  pool: WorkerPool;
  processStageAJob: ProcessStageAJob;
  supportedJobTypes: readonly string[];
}> {
  const database = await import("@workspace/db/worker");
  onPoolCreated(database.workerPool);
  const worker = await import("./index");

  return {
    pool: database.workerPool,
    processStageAJob: worker.processOneStageAJob,
    supportedJobTypes: database.stageAJobTypes,
  };
}

export async function runWorker(options: RunWorkerOptions = {}): Promise<number> {
  let pool: WorkerPool | undefined;
  let signals: SignalSource | undefined;
  let stopping = false;
  const stop = (): void => {
    stopping = true;
  };
  let exitCode = 0;

  try {
    validateWorkerEnvironment(options.env);

    const loaded =
      options.pool && options.processStageAJob && options.supportedJobTypes
        ? {
            pool: options.pool,
            processStageAJob: options.processStageAJob,
            supportedJobTypes: options.supportedJobTypes,
          }
        : await loadWorkerDependencies((createdPool) => {
            pool = createdPool;
          });
    pool ??= loaded.pool;
    signals = options.signals ?? (process as unknown as SignalSource);
    const sleep = options.sleep ?? defaultSleep;
    const workerId = options.workerId ?? defaultWorkerId();

    signals.on("SIGINT", stop);
    signals.on("SIGTERM", stop);
    await assertWorkerIdentity(pool);

    let idleBackoffMs = MIN_IDLE_BACKOFF_MS;
    while (!stopping) {
      const processed = await loaded.processStageAJob({
        workerId,
        supportedJobTypes: loaded.supportedJobTypes,
      });

      if (processed) {
        idleBackoffMs = MIN_IDLE_BACKOFF_MS;
        continue;
      }

      await sleep(idleBackoffMs);
      idleBackoffMs = Math.min(idleBackoffMs * 2, MAX_IDLE_BACKOFF_MS);
    }
  } catch {
    exitCode = 1;
    if (!stopping) {
      console.error("Stage A Worker stopped after an unrecoverable failure.");
    }
  } finally {
    if (signals) {
      signals.off("SIGINT", stop);
      signals.off("SIGTERM", stop);
    }
    if (pool) {
      try {
        await pool.end();
      } catch {
        exitCode = 1;
        console.error("Stage A Worker pool shutdown failed.");
      }
    }
  }

  return exitCode;
}