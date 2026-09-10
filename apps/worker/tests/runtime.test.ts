import assert from "node:assert/strict";
import test from "node:test";
import {
  assertWorkerIdentity,
  MAX_IDLE_BACKOFF_MS,
  MIN_IDLE_BACKOFF_MS,
  runWorker,
  validateWorkerEnvironment,
  type SignalSource,
  type WorkerClient,
  type WorkerPool,
} from "../src/runtime";

const workerEnvironment = (): NodeJS.ProcessEnv => ({
  DATABASE_WORKER_URL: "synthetic-worker-credential",
});

function identityPool(identity: Record<string, unknown>): WorkerPool {
  const client: WorkerClient = {
    query: async () => ({
      rows: [
        {
          session_user: "workos_worker",
          current_user: "workos_worker",
          superuser: false,
          bypassrls: false,
          createrole: false,
          createdb: false,
          replication: false,
          inherit: false,
          ...identity,
        },
      ],
    }),
    release: () => undefined,
  };
  return {
    connect: async () => client,
    end: async () => undefined,
  };
}

class TestSignals implements SignalSource {
  private readonly listeners = new Map<
    "SIGINT" | "SIGTERM",
    Set<() => void>
  >();

  on(signal: "SIGINT" | "SIGTERM", listener: () => void): void {
    const listeners = this.listeners.get(signal) ?? new Set();
    listeners.add(listener);
    this.listeners.set(signal, listeners);
  }

  off(signal: "SIGINT" | "SIGTERM", listener: () => void): void {
    this.listeners.get(signal)?.delete(listener);
  }

  emit(signal: "SIGINT" | "SIGTERM"): void {
    for (const listener of this.listeners.get(signal) ?? []) {
      listener();
    }
  }
}

test("requires DATABASE_WORKER_URL", () => {
  assert.throws(
    () => validateWorkerEnvironment({}),
    /DATABASE_WORKER_URL must be set/,
  );
});

test("rejects forbidden runtime and migration database URLs", () => {
  for (const name of ["DATABASE_RUNTIME_URL", "DATABASE_MIGRATION_URL"]) {
    const environment = workerEnvironment();
    environment[name] = "";
    assert.throws(
      () => validateWorkerEnvironment(environment),
      new RegExp(`${name} must not be present`),
    );
  }
});

const invalidIdentityCases: Array<
  [string, Record<string, unknown>, string | boolean]
> = [
  ["session_user", { session_user: "workos_runtime" }, "workos_runtime"],
  ["current_user", { current_user: "workos_runtime" }, "workos_runtime"],
  ["SUPERUSER", { superuser: true }, true],
  ["BYPASSRLS", { bypassrls: true }, true],
  ["CREATEROLE", { createrole: true }, true],
  ["CREATEDB", { createdb: true }, true],
  ["REPLICATION", { replication: true }, true],
  ["INHERIT", { inherit: true }, true],
];

for (const [attribute, override, expectedValue] of invalidIdentityCases) {
  test(`fails closed when ${attribute} is ${String(expectedValue)}`, async () => {
    const pool = identityPool({
      session_user: "workos_worker",
      current_user: "workos_worker",
      superuser: false,
      bypassrls: false,
      createrole: false,
      createdb: false,
      replication: false,
      inherit: false,
      ...override,
    });

    await assert.rejects(
      () => assertWorkerIdentity(pool),
      /Worker database identity check failed/,
    );
  });
}

test("shuts down cleanly on SIGTERM and closes the pool", async () => {
  const signals = new TestSignals();
  let endCalls = 0;
  let processCalls = 0;
  let sleepCalls = 0;
  const pool = identityPool({
    session_user: "workos_worker",
    current_user: "workos_worker",
    superuser: false,
    bypassrls: false,
  });
  pool.end = async () => {
    endCalls += 1;
  };

  const exitCode = await runWorker({
    env: workerEnvironment(),
    pool,
    processStageAJob: async () => {
      processCalls += 1;
      return false;
    },
    supportedJobTypes: [],
    signals,
    sleep: async () => {
      sleepCalls += 1;
      signals.emit("SIGTERM");
    },
  });

  assert.equal(exitCode, 0);
  assert.equal(processCalls, 1);
  assert.equal(sleepCalls, 1);
  assert.equal(endCalls, 1);
});

test("backs off between idle polls and caps the delay", async () => {
  const signals = new TestSignals();
  const delays: number[] = [];
  let processCalls = 0;
  const pool = identityPool({
    session_user: "workos_worker",
    current_user: "workos_worker",
    superuser: false,
    bypassrls: false,
  });

  const exitCode = await runWorker({
    env: workerEnvironment(),
    pool,
    processStageAJob: async () => {
      processCalls += 1;
      return false;
    },
    supportedJobTypes: [],
    signals,
    sleep: async (delay) => {
      delays.push(delay);
      if (delays.length === 6) {
        signals.emit("SIGINT");
      }
    },
  });

  assert.equal(exitCode, 0);
  assert.equal(processCalls, 6);
  assert.deepEqual(delays, [
    MIN_IDLE_BACKOFF_MS,
    MIN_IDLE_BACKOFF_MS * 2,
    MIN_IDLE_BACKOFF_MS * 4,
    MIN_IDLE_BACKOFF_MS * 8,
    MIN_IDLE_BACKOFF_MS * 16,
    MAX_IDLE_BACKOFF_MS,
  ]);
});

test("does not log forbidden environment values when validation fails", async () => {
  const secret = "synthetic-environment-credential";
  const messages: string[] = [];
  const originalError = console.error;
  console.error = (...args: unknown[]) => {
    messages.push(args.map(String).join(" "));
  };

  try {
    const exitCode = await runWorker({
      env: {
        DATABASE_WORKER_URL: "synthetic-worker-credential",
        DATABASE_RUNTIME_URL: secret,
      },
      signals: new TestSignals(),
    });

    assert.equal(exitCode, 1);
  } finally {
    console.error = originalError;
  }

  assert.equal(messages.join("\n"), "Stage A Worker stopped after an unrecoverable failure.");
  assert.ok(!messages.join("\n").includes(secret));
});

test("does not log secret values when startup fails", async () => {
  const secret = "synthetic-startup-credential";
  const messages: string[] = [];
  const originalError = console.error;
  console.error = (...args: unknown[]) => {
    messages.push(args.map(String).join(" "));
  };

  try {
    const exitCode = await runWorker({
      env: { DATABASE_WORKER_URL: secret },
      pool: {
        connect: async () => {
          throw new Error(secret);
        },
        end: async () => undefined,
      },
      processStageAJob: async () => false,
      supportedJobTypes: [],
      signals: new TestSignals(),
    });

    assert.equal(exitCode, 1);
  } finally {
    console.error = originalError;
  }

  assert.equal(messages.join("\n"), "Stage A Worker stopped after an unrecoverable failure.");
  assert.ok(!messages.join("\n").includes(secret));
});