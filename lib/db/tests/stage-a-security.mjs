import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
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
      `DATABASE_${purpose.toUpperCase()}_URL must be set. Security tests do not fall back to DATABASE_URL.`,
    );
  }
}

assert.notEqual(requiredUrls.migration, requiredUrls.runtime);
assert.notEqual(requiredUrls.migration, requiredUrls.worker);
assert.notEqual(requiredUrls.runtime, requiredUrls.worker);

const adminClient = new Client({
  connectionString: requiredUrls.migration,
  application_name: "work-os-stage-a-security-admin",
});
const runtimeClient = new Client({
  connectionString: requiredUrls.runtime,
  application_name: "work-os-stage-a-security-api",
});
const workerClient = new Client({
  connectionString: requiredUrls.worker,
  application_name: "work-os-stage-a-security-worker",
});

const results = [];
let testNumber = 0;
let savepointNumber = 0;

async function test(name, client, operation, { commit = false } = {}) {
  testNumber += 1;
  try {
    await client.query("begin");
    await operation();
    await client.query(commit ? "commit" : "rollback");
    results.push({ name, passed: true });
    process.stdout.write(`PASS ${name}\n`);
  } catch (error) {
    await client.query("rollback").catch(() => {});
    results.push({ name, passed: false, error });
    process.stderr.write(`FAIL ${name}: ${error.message}\n`);
  }
}

async function expectDatabaseError(client, sql, params = []) {
  const savepoint = `expected_${++savepointNumber}`;
  await client.query(`savepoint ${savepoint}`);
  try {
    await client.query(sql, params);
  } catch {
    await client.query(`rollback to savepoint ${savepoint}`);
    await client.query(`release savepoint ${savepoint}`);
    return;
  }
  await client.query(`release savepoint ${savepoint}`);
  throw new Error("Expected database operation to fail");
}

async function setSetting(client, name, value) {
  await client.query("select set_config($1, $2, true)", [name, value]);
}

const seed = {
  tenantId: "10000000-0000-4000-8000-000000000001",
  workspaceId: "20000000-0000-4000-8000-000000000001",
  operatorUserId: "30000000-0000-4000-8000-000000000001",
  assignmentId: "60000000-0000-4000-8000-000000000001",
  taskId: "71000000-0000-4000-8000-000000000001",
};

const tenantB = randomUUID();
const workspaceB = randomUUID();
const userB = randomUUID();
const membershipB = randomUUID();
const principalB = randomUUID();
const workObjectB = randomUUID();
const createdContextIds = [];
const createdEffectIds = [];
let enqueuedJobId;
let claimedJob;

await Promise.all([
  adminClient.connect(),
  runtimeClient.connect(),
  workerClient.connect(),
]);

try {
  await adminClient.query("begin");
  await adminClient.query(
    "insert into workos.tenants (id, name) values ($1, 'Isolation Test Tenant')",
    [tenantB],
  );
  await adminClient.query(
    `insert into workos.workspaces
       (id, tenant_id, name, workspace_type, security_domain)
     values ($1, $2, 'Isolation Workspace', 'TEST', $3)`,
    [workspaceB, tenantB, `test-${workspaceB}`],
  );
  await adminClient.query(
    "insert into workos.users (id, display_name) values ($1, 'Isolation User')",
    [userB],
  );
  await adminClient.query(
    `insert into workos.workspace_memberships
       (id, tenant_id, workspace_id, user_id, role)
     values ($1, $2, $3, $4, 'OPERATOR')`,
    [membershipB, tenantB, workspaceB, userB],
  );
  await adminClient.query(
    `insert into workos.principals
       (id, tenant_id, workspace_id, principal_type, display_name)
     values ($1, $2, $3, 'PERSON', 'Isolation Principal')`,
    [principalB, tenantB, workspaceB],
  );
  await adminClient.query(
    `insert into workos.work_objects
       (id, tenant_id, workspace_id, work_type, title)
     values ($1, $2, $3, 'TEST', 'Tenant B private object')`,
    [workObjectB, tenantB, workspaceB],
  );
  await adminClient.query("commit");

  await test(
    "migration-admin and Work OS role memberships stay within the approved boundary",
    adminClient,
    async () => {
      const membershipResult = await adminClient.query(`
        select member.rolname as member, granted.rolname as granted_role
        from pg_auth_members membership
        join pg_roles member on member.oid = membership.member
        join pg_roles granted on granted.oid = membership.roleid
        where member.rolname in (
          'neondb_owner',
          'workos_runtime',
          'workos_worker',
          'workos_migrator',
          'workos_schema_owner',
          'workos_security_definer'
        )
          and granted.rolname in (
            'neondb_owner',
            'workos_runtime',
            'workos_worker',
            'workos_migrator',
            'workos_schema_owner',
            'workos_security_definer'
          )
        order by member.rolname, granted.rolname
      `);
      assert.deepEqual(membershipResult.rows, [
        { member: "neondb_owner", granted_role: "workos_schema_owner" },
        { member: "neondb_owner", granted_role: "workos_security_definer" },
        { member: "workos_migrator", granted_role: "workos_schema_owner" },
      ]);

      const runtimeMemberships = await adminClient.query(`
        select 1
        from pg_auth_members membership
        join pg_roles member on member.oid = membership.member
        where member.rolname = 'workos_runtime'
      `);
      assert.equal(runtimeMemberships.rowCount, 0);

      const workerMemberships = await adminClient.query(`
        select 1
        from pg_auth_members membership
        join pg_roles member on member.oid = membership.member
        where member.rolname = 'workos_worker'
      `);
      assert.equal(workerMemberships.rowCount, 0);
    },
  );

  await test(
    "runtime role has no control-plane table privileges",
    adminClient,
    async () => {
      const result = await adminClient.query(`
        select count(*)::int as count
        from information_schema.role_table_grants
        where grantee in ('workos_runtime', 'workos_worker')
          and table_schema = 'workos_control'
          and table_name = 'job_envelopes'
      `);
      assert.equal(result.rows[0].count, 0);
    },
  );

  await test("RLS returns no tasks without context", runtimeClient, async () => {
    const result = await runtimeClient.query("select id from workos.tasks");
    assert.equal(result.rowCount, 0);
  });

  await test("valid normal context sees only its workspace", runtimeClient, async () => {
    await setSetting(runtimeClient, "workos.access_mode", "NORMAL");
    await setSetting(runtimeClient, "workos.user_id", seed.operatorUserId);
    await setSetting(runtimeClient, "workos.tenant_id", seed.tenantId);
    await setSetting(runtimeClient, "workos.workspace_id", seed.workspaceId);
    await setSetting(runtimeClient, "workos.context_version", "1");
    const result = await runtimeClient.query("select id from workos.tasks order by id");
    assert.equal(result.rowCount, 2);
  });

  await test("mismatched tenant context fails closed", runtimeClient, async () => {
    await setSetting(runtimeClient, "workos.access_mode", "NORMAL");
    await setSetting(runtimeClient, "workos.user_id", seed.operatorUserId);
    await setSetting(runtimeClient, "workos.tenant_id", randomUUID());
    await setSetting(runtimeClient, "workos.workspace_id", seed.workspaceId);
    await setSetting(runtimeClient, "workos.context_version", "1");
    const result = await runtimeClient.query("select id from workos.tasks");
    assert.equal(result.rowCount, 0);
  });

  await test("cross-tenant composite foreign key rejects mixed object", adminClient, async () => {
    await expectDatabaseError(
      adminClient,
      `insert into workos.tasks
         (tenant_id, workspace_id, work_object_id, intent, completion_condition)
       values ($1, $2, $3, 'Invalid mixed tenant task', '{"type":"test_gate","suite":"invalid"}')`,
      [seed.tenantId, seed.workspaceId, workObjectB],
    );
  });

  await test(
    "AccessCatalog discovers only current user's contexts",
    runtimeClient,
    async () => {
      await setSetting(runtimeClient, "workos.access_mode", "ACCESS_CATALOG");
      await setSetting(runtimeClient, "workos.user_id", seed.operatorUserId);
      const result = await runtimeClient.query(
        "select * from workos_security.get_access_catalog_for_current_user()",
      );
      assert.ok(result.rowCount >= 1);
      assert.ok(result.rows.every((row) => row.tenant_id === seed.tenantId));
    },
  );

  await test(
    "AccessCatalog cannot be supplied another browser user id",
    adminClient,
    async () => {
      const signature = await adminClient.query(`
        select pronargs
        from pg_proc
        where oid = 'workos_security.get_access_catalog_for_current_user()'::regprocedure
      `);
      assert.equal(signature.rows[0].pronargs, 0);
    },
  );

  await test("another user cannot discover the first user's contexts", runtimeClient, async () => {
    await setSetting(runtimeClient, "workos.access_mode", "ACCESS_CATALOG");
    await setSetting(runtimeClient, "workos.user_id", userB);
    const result = await runtimeClient.query(
      "select * from workos_security.get_access_catalog_for_current_user()",
    );
    assert.equal(result.rowCount, 1);
    assert.equal(result.rows[0].tenant_id, tenantB);
  });

  await adminClient.query(
    "update workos.workspace_memberships set status = 'REVOKED', context_version = context_version + 1 where id = $1",
    [membershipB],
  );
  await test("revoked membership disappears immediately", runtimeClient, async () => {
    await setSetting(runtimeClient, "workos.access_mode", "ACCESS_CATALOG");
    await setSetting(runtimeClient, "workos.user_id", userB);
    const result = await runtimeClient.query(
      "select * from workos_security.get_access_catalog_for_current_user()",
    );
    assert.equal(result.rowCount, 0);
  });
  await adminClient.query(
    "update workos.workspace_memberships set status = 'ACTIVE', context_version = 1 where id = $1",
    [membershipB],
  );

  await test("PortfolioContext returns only safe projected metadata", runtimeClient, async () => {
    await setSetting(runtimeClient, "workos.access_mode", "ACCESS_CATALOG");
    await setSetting(runtimeClient, "workos.user_id", seed.operatorUserId);
    const opened = await runtimeClient.query(
      "select workos_security.open_portfolio_context('Stage A security test') as id",
    );
    const contextId = opened.rows[0].id;
    createdContextIds.push(contextId);
    const result = await runtimeClient.query(
      "select * from workos_security.get_portfolio_metadata($1)",
      [contextId],
    );
    assert.equal(result.rowCount, 1);
    assert.deepEqual(Object.keys(result.rows[0]).sort(), [
      "age_seconds",
      "assignment_id",
      "category",
      "refreshed_at",
      "sla_due_at",
      "status",
      "tenant_id",
      "tenant_name",
      "urgency",
      "workspace_id",
      "workspace_name",
    ]);
  });

  await test("portfolio context is inaccessible to a different user", runtimeClient, async () => {
    await setSetting(runtimeClient, "workos.access_mode", "ACCESS_CATALOG");
    await setSetting(runtimeClient, "workos.user_id", seed.operatorUserId);
    const opened = await runtimeClient.query(
      "select workos_security.open_portfolio_context('Ownership test') as id",
    );
    const contextId = opened.rows[0].id;
    createdContextIds.push(contextId);
    await setSetting(runtimeClient, "workos.user_id", userB);
    const result = await runtimeClient.query(
      "select * from workos_security.get_portfolio_metadata($1)",
      [contextId],
    );
    assert.equal(result.rowCount, 0);
  });

  const dedupeKey = `security-test-${randomUUID()}`;
  await test(
    "normal context enqueues through controlled function",
    runtimeClient,
    async () => {
      await setSetting(runtimeClient, "workos.access_mode", "NORMAL");
      await setSetting(runtimeClient, "workos.user_id", seed.operatorUserId);
      await setSetting(runtimeClient, "workos.tenant_id", seed.tenantId);
      await setSetting(runtimeClient, "workos.workspace_id", seed.workspaceId);
      await setSetting(runtimeClient, "workos.context_version", "1");
      const result = await runtimeClient.query(
        "select workos_control.enqueue_job('TASK_RECONCILE', $1, now(), $2) as id",
        [seed.taskId, dedupeKey],
      );
      enqueuedJobId = result.rows[0].id;
      assert.ok(enqueuedJobId);
    },
    { commit: true },
  );

  await test("worker cannot directly select job envelopes", workerClient, async () => {
    await expectDatabaseError(workerClient, "select * from workos_control.job_envelopes");
  });

  await test(
    "worker claims one due job through constrained function",
    workerClient,
    async () => {
      const result = await workerClient.query(
        "select * from workos_control.claim_due_job('stage-a-test-worker', array['TASK_RECONCILE'], 60)",
      );
      assert.equal(result.rowCount, 1);
      claimedJob = result.rows[0];
    },
    { commit: true },
  );

  await test("duplicate worker cannot claim the same job", workerClient, async () => {
    const result = await workerClient.query(
      "select * from workos_control.claim_due_job('second-worker', array['TASK_RECONCILE'], 60)",
    );
    assert.equal(result.rowCount, 0);
  });

  await test("SYSTEM_JOB can read only the claimed task", workerClient, async () => {
    assert.ok(claimedJob, "worker claim fixture was not created");
    await setSetting(workerClient, "workos.access_mode", "SYSTEM_JOB");
    await setSetting(workerClient, "workos.system_job_id", claimedJob.job_id);
    await setSetting(workerClient, "workos.claim_token", claimedJob.claim_token);
    await setSetting(workerClient, "workos.tenant_id", claimedJob.tenant_id);
    await setSetting(workerClient, "workos.workspace_id", claimedJob.workspace_id);
    const result = await workerClient.query("select id from workos.tasks order by id");
    assert.equal(result.rowCount, 1);
    assert.equal(result.rows[0].id, seed.taskId);
  });

  await test("SYSTEM_JOB cannot broaden tenant access with variables", workerClient, async () => {
    assert.ok(claimedJob, "worker claim fixture was not created");
    await setSetting(workerClient, "workos.access_mode", "SYSTEM_JOB");
    await setSetting(workerClient, "workos.system_job_id", claimedJob.job_id);
    await setSetting(workerClient, "workos.claim_token", claimedJob.claim_token);
    await setSetting(workerClient, "workos.tenant_id", tenantB);
    await setSetting(workerClient, "workos.workspace_id", workspaceB);
    const result = await workerClient.query("select id from workos.tasks");
    assert.equal(result.rowCount, 0);
  });

  await test("job envelope scope fields are immutable", adminClient, async () => {
    assert.ok(claimedJob, "worker claim fixture was not created");
    await expectDatabaseError(
      adminClient,
      "update workos_control.job_envelopes set tenant_id = $1 where id = $2",
      [tenantB, claimedJob.job_id],
    );
  });

  await test("invalid claim token fails closed", workerClient, async () => {
    assert.ok(claimedJob, "worker claim fixture was not created");
    await setSetting(workerClient, "workos.access_mode", "SYSTEM_JOB");
    await setSetting(workerClient, "workos.system_job_id", claimedJob.job_id);
    await setSetting(workerClient, "workos.claim_token", randomUUID());
    await setSetting(workerClient, "workos.tenant_id", claimedJob.tenant_id);
    await setSetting(workerClient, "workos.workspace_id", claimedJob.workspace_id);
    const result = await workerClient.query("select id from workos.tasks");
    assert.equal(result.rowCount, 0);
  });

  await test("effect instances allow separate logical occurrences", adminClient, async () => {
    const first = randomUUID();
    const second = randomUUID();
    createdEffectIds.push(first, second);
    await adminClient.query(
      `insert into workos.effect_instances
         (id, tenant_id, workspace_id, task_id, transition_code, occurrence_id, effect_fingerprint)
       values
         ($1, $3, $4, $5, $6, $7, $8),
         ($2, $3, $4, $5, $6, $9, $10)`,
      [
        first,
        second,
        seed.tenantId,
        seed.workspaceId,
        seed.taskId,
        "FOLLOW_UP",
        `task:${seed.taskId}:follow-up:1`,
        `fingerprint-${first}`,
        `task:${seed.taskId}:follow-up:2`,
        `fingerprint-${second}`,
      ],
    );
    const result = await adminClient.query(
      "select count(*)::int as count from workos.effect_instances where id in ($1, $2)",
      [first, second],
    );
    assert.equal(result.rows[0].count, 2);
  });

  await test("one logical effect instance receives one execution guard", adminClient, async () => {
    const effectId = randomUUID();
    createdEffectIds.push(effectId);
    await adminClient.query(
      `insert into workos.effect_instances
         (id, tenant_id, workspace_id, task_id, transition_code, occurrence_id, effect_fingerprint)
       values ($1, $2, $3, $4, 'VERIFY', $5, $6)`,
      [
        effectId,
        seed.tenantId,
        seed.workspaceId,
        seed.taskId,
        `task:${seed.taskId}:verify:${effectId}`,
        `fingerprint-${effectId}`,
      ],
    );
    await adminClient.query(
      `insert into workos.execution_guards
         (tenant_id, workspace_id, effect_instance_id, idempotency_key)
       values ($1, $2, $3, $4)`,
      [seed.tenantId, seed.workspaceId, effectId, `guard-${effectId}`],
    );
    await expectDatabaseError(
      adminClient,
      `insert into workos.execution_guards
         (tenant_id, workspace_id, effect_instance_id, idempotency_key)
       values ($1, $2, $3, $4)`,
      [seed.tenantId, seed.workspaceId, effectId, `second-${effectId}`],
    );
  });

  await test("append-only activity history denies runtime updates", runtimeClient, async () => {
    await expectDatabaseError(
      runtimeClient,
      "update workos.activity_events set event_type = 'REWRITTEN'",
    );
  });

  await test("append-only audit history denies runtime deletes", runtimeClient, async () => {
    await expectDatabaseError(runtimeClient, "delete from workos.audit_records");
  });
} finally {
  await Promise.all([
    runtimeClient.end().catch(() => {}),
    workerClient.end().catch(() => {}),
  ]);

  try {
    await adminClient.query("begin");
    if (createdContextIds.length > 0) {
      await adminClient.query(
        "delete from workos.portfolio_contexts where id = any($1::uuid[])",
        [createdContextIds],
      );
    }
    if (createdEffectIds.length > 0) {
      await adminClient.query(
        "delete from workos.execution_guards where effect_instance_id = any($1::uuid[])",
        [createdEffectIds],
      );
      await adminClient.query(
        "delete from workos.effect_instances where id = any($1::uuid[])",
        [createdEffectIds],
      );
    }
    if (enqueuedJobId) {
      await adminClient.query(
        "delete from workos.job_claim_events where job_id = $1",
        [enqueuedJobId],
      );
      await adminClient.query(
        "delete from workos_control.job_envelopes where id = $1",
        [enqueuedJobId],
      );
    }
    await adminClient.query("delete from workos.work_objects where id = $1", [workObjectB]);
    await adminClient.query("delete from workos.principals where id = $1", [principalB]);
    await adminClient.query("delete from workos.workspace_memberships where id = $1", [
      membershipB,
    ]);
    await adminClient.query("delete from workos.workspaces where id = $1", [workspaceB]);
    await adminClient.query("delete from workos.users where id = $1", [userB]);
    await adminClient.query("delete from workos.tenants where id = $1", [tenantB]);
    await adminClient.query("commit");
  } catch (error) {
    await adminClient.query("rollback").catch(() => {});
    process.stderr.write(`Cleanup failed: ${error.message}\n`);
  }
  await adminClient.end().catch(() => {});
}

const passed = results.filter((result) => result.passed).length;
const failed = results.length - passed;
process.stdout.write(`RESULT ${passed} passed, ${failed} failed\n`);
if (failed > 0) {
  process.exitCode = 1;
}