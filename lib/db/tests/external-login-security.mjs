import assert from "node:assert/strict";
import pg from "pg";

const { Client } = pg;

const requiredUrls = {
  migration: process.env.DATABASE_MIGRATION_URL,
  runtime: process.env.DATABASE_RUNTIME_URL,
  worker: process.env.DATABASE_WORKER_URL,
};

for (const [purpose, value] of Object.entries(requiredUrls)) {
  if (!value) {
    throw new Error(
      `DATABASE_${purpose.toUpperCase()}_URL must be set. Identity tests do not fall back to DATABASE_URL.`,
    );
  }
}

const results = [];

assert.notEqual(requiredUrls.migration, requiredUrls.runtime);
assert.notEqual(requiredUrls.migration, requiredUrls.worker);
assert.notEqual(requiredUrls.runtime, requiredUrls.worker);

async function test(name, operation) {
  try {
    await operation();
    results.push({ name, passed: true });
    process.stdout.write(`PASS ${name}\n`);
  } catch (error) {
    results.push({ name, passed: false, error });
    process.stderr.write(`FAIL ${name}: ${error.message}\n`);
  }
}

async function expectPermissionDenied(client, sql, params = []) {
  try {
    await client.query(sql, params);
  } catch (error) {
    assert.match(
      String(error.message),
      /permission denied|must be member of role|not permitted/i,
    );
    return;
  }
  throw new Error("Expected the database to deny the operation");
}

async function readIdentity(client) {
  const result = await client.query(`
    select
      session_user,
      current_user,
      role.rolsuper,
      role.rolbypassrls,
      role.rolcreaterole,
      role.rolcreatedb,
      role.rolinherit,
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
        as can_assume_migrator,
      pg_has_role(current_user, 'workos_runtime', 'MEMBER')
        as is_runtime_member,
      pg_has_role(current_user, 'workos_worker', 'MEMBER')
        as is_worker_member
    from pg_roles role
    where role.rolname = current_user
  `);
  assert.equal(result.rowCount, 1);
  return result.rows[0];
}

async function connect(url, applicationName) {
  const client = new Client({
    connectionString: url,
    application_name: applicationName,
  });
  await client.connect();
  return client;
}

const migrationClient = await connect(
  requiredUrls.migration,
  "work-os-identity-test-migrator",
);
const runtimeClient = await connect(
  requiredUrls.runtime,
  "work-os-identity-test-api",
);
const workerClient = await connect(
  requiredUrls.worker,
  "work-os-identity-test-worker",
);

try {
  let migrationIdentity;

  await test("migration URL uses a separate non-application identity", async () => {
    migrationIdentity = await readIdentity(migrationClient);
    assert.notEqual(migrationIdentity.current_user, "workos_runtime");
    assert.notEqual(migrationIdentity.current_user, "workos_worker");
  });

  await test("actual API connection is the least-privilege runtime login", async () => {
    const identity = await readIdentity(runtimeClient);
    assert.equal(identity.session_user, "workos_runtime");
    assert.equal(identity.current_user, "workos_runtime");
    assert.equal(identity.rolsuper, false);
    assert.equal(identity.rolbypassrls, false);
    assert.equal(identity.rolcreaterole, false);
    assert.equal(identity.rolcreatedb, false);
    assert.equal(identity.rolinherit, false);
    assert.equal(identity.owns_workos_objects, false);
    assert.equal(identity.can_assume_schema_owner, false);
    assert.equal(identity.can_assume_security_definer, false);
    assert.equal(identity.can_assume_migrator, false);
    assert.equal(identity.is_worker_member, false);
  });

  await test("actual worker connection is the least-privilege worker login", async () => {
    const identity = await readIdentity(workerClient);
    assert.equal(identity.session_user, "workos_worker");
    assert.equal(identity.current_user, "workos_worker");
    assert.equal(identity.rolsuper, false);
    assert.equal(identity.rolbypassrls, false);
    assert.equal(identity.rolcreaterole, false);
    assert.equal(identity.rolcreatedb, false);
    assert.equal(identity.rolinherit, false);
    assert.equal(identity.owns_workos_objects, false);
    assert.equal(identity.can_assume_schema_owner, false);
    assert.equal(identity.can_assume_security_definer, false);
    assert.equal(identity.can_assume_migrator, false);
    assert.equal(identity.is_runtime_member, false);
  });

  for (const [label, client, expectedRole] of [
    ["API", runtimeClient, "workos_runtime"],
    ["worker", workerClient, "workos_worker"],
  ]) {
    await test(`${label} cannot SET ROLE to the schema owner`, async () => {
      await expectPermissionDenied(client, "set role workos_schema_owner");
      await expectPermissionDenied(client, "set role neondb_owner");
    });

    await test(`${label} cannot SET ROLE to the RLS-bypass definer`, async () => {
      await expectPermissionDenied(client, "set role workos_security_definer");
      await expectPermissionDenied(
        client,
        `set role ${expectedRole === "workos_runtime" ? "workos_worker" : "workos_runtime"}`,
      );
    });

    await test(`${label} cannot SET ROLE to the migrator`, async () => {
      await expectPermissionDenied(client, "set role workos_migrator");
    });

    await test(`${label} RESET ROLE remains least privilege`, async () => {
      await client.query("reset role");
      const identity = await readIdentity(client);
      assert.equal(identity.session_user, expectedRole);
      assert.equal(identity.current_user, expectedRole);
      assert.equal(identity.rolsuper, false);
      assert.equal(identity.rolbypassrls, false);
    });

    await test(`${label} cannot assume the external migration login`, async () => {
      const migrationRole = migrationIdentity.current_user;
      assert.match(migrationRole, /^[a-z_][a-z0-9_$-]*$/i);
      await expectPermissionDenied(
        client,
        `set role "${migrationRole}"`,
      );
    });
  }

  await test("API cannot claim worker jobs", async () => {
    await expectPermissionDenied(
      runtimeClient,
      "select * from workos_control.claim_due_job($1, $2::text[], $3)",
      ["api-must-not-claim", ["TASK_RECONCILE"], 60],
    );
  });

  await test("API cannot directly read job envelopes", async () => {
    await expectPermissionDenied(
      runtimeClient,
      "select * from workos_control.job_envelopes",
    );
  });

  await test("worker cannot directly read job envelopes", async () => {
    await expectPermissionDenied(
      workerClient,
      "select * from workos_control.job_envelopes",
    );
  });

  await test("worker receives no normal application data without a live claim", async () => {
    const result = await workerClient.query(
      "select count(*)::int as count from workos.tasks",
    );
    assert.equal(result.rows[0].count, 0);
  });

  await test("worker cannot use AccessCatalog", async () => {
    await expectPermissionDenied(
      workerClient,
      "select * from workos_security.get_access_catalog_for_current_user()",
    );
  });
} finally {
  await Promise.all([
    migrationClient.end(),
    runtimeClient.end(),
    workerClient.end(),
  ]);
}

const passed = results.filter((result) => result.passed).length;
const failed = results.length - passed;
process.stdout.write(`RESULT ${passed} passed, ${failed} failed\n`);
if (failed > 0) {
  process.exitCode = 1;
}