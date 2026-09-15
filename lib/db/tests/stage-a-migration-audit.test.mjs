import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  AuditInvariantError,
  EXPECTED_MIGRATION_FILENAMES,
  EXPECTED_POLICIES,
  EXPECTED_TABLE_ACL,
  SECURITY_DEFINER_MANIFEST,
  assertReadOnlyQueryManifest,
  deriveFunctionExecuteAllowlists,
  effectiveMembershipQuery,
  executeAuditCli,
  loadMigrationManifest,
  normalizeExpression,
  normalizeSignature,
  requireMigrationEnvironment,
  safeResultLine,
  safeQuery,
  validateFunctionExecute,
  validatePolicies,
  validateSchemaAcl,
  validateLedgerPrimaryKey,
  validateJobEnvelopeControlPlane,
  validateMemberships,
  validateMigrationLedger,
  validateMigrationIdentity,
  validateNoPublicFunctionExecute,
  validateCustomerZeroSeed,
  validateOwnership,
  validatePublicSchemaHardening,
  validateSecurityDefinerFunctions,
  validateTableAcl,
  CATALOG_QUERIES,
} from "./stage-a-migration-audit-lib.mjs";

const syntheticMigrationUrl = "synthetic-migration-credential";
const syntheticSecret = "synthetic-secret-that-must-never-be-logged";
const syntheticRawError = "raw-hostname.neon.tech rejected synthetic-password";

test("only DATABASE_MIGRATION_URL is accepted", () => {
  assert.equal(
    requireMigrationEnvironment({
      DATABASE_MIGRATION_URL: syntheticMigrationUrl,
    }),
    syntheticMigrationUrl,
  );
});

test("runtime and worker credential presence fails closed", () => {
  for (const name of ["DATABASE_RUNTIME_URL", "DATABASE_WORKER_URL"]) {
    assert.throws(
      () =>
        requireMigrationEnvironment({
          DATABASE_MIGRATION_URL: syntheticMigrationUrl,
          [name]: "",
        }),
      AuditInvariantError,
    );
  }
});

test("DATABASE_URL is never a fallback", () => {
  assert.throws(
    () => requireMigrationEnvironment({ DATABASE_URL: syntheticSecret }),
    AuditInvariantError,
  );
});

test("migration identity follows the provider-neutral runner contract", () => {
  assert.equal(
    validateMigrationIdentity({
      session_user: "migration_admin",
      current_user: "migration_admin",
      rolcanlogin: true,
      rolsuper: false,
      rolcreaterole: true,
      can_assume_schema_owner: true,
      can_assume_security_definer: true,
    }),
    true,
  );
  assert.equal(
    validateMigrationIdentity({
      session_user: "migration_admin",
      current_user: "migration_admin",
      rolcanlogin: true,
      rolsuper: true,
      rolcreaterole: true,
      can_assume_schema_owner: true,
      can_assume_security_definer: true,
    }),
    false,
  );
});

test("migration manifest and checksums are derived from exactly eight files", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "workos-audit-"));
  try {
    for (const [index, filename] of EXPECTED_MIGRATION_FILENAMES.entries()) {
      await writeFile(path.join(directory, filename), `select ${index};\n`);
    }
    const manifest = await loadMigrationManifest(directory);
    assert.deepEqual(
      manifest.map(({ filename }) => filename),
      EXPECTED_MIGRATION_FILENAMES,
    );
    assert.equal(
      manifest[0].checksum,
      createHash("sha256").update("select 0;\n").digest("hex"),
    );

    await writeFile(path.join(directory, "0009_unexpected.sql"), "select 9;\n");
    await assert.rejects(
      () => loadMigrationManifest(directory),
      AuditInvariantError,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("missing, extra, and wrong ledger rows fail", () => {
  const manifest = EXPECTED_MIGRATION_FILENAMES.map((filename, index) => ({
    filename,
    checksum: `${index}`.padStart(64, "0"),
    sql: "",
  }));
  const rows = manifest.map(({ filename, checksum }) => ({
    filename,
    checksum,
    applied_at: new Date(),
  }));
  assert.equal(validateMigrationLedger(rows, manifest), true);
  assert.equal(validateMigrationLedger(rows.slice(1), manifest), false);
  assert.equal(
    validateMigrationLedger(
      [...rows.slice(1), { ...rows[0], filename: rows[1].filename }],
      manifest,
    ),
    false,
  );
  assert.equal(
    validateMigrationLedger(
      [...rows, { filename: "extra.sql", checksum: "x", applied_at: new Date() }],
      manifest,
    ),
    false,
  );
  assert.equal(
    validateMigrationLedger(
      rows.map((row, index) =>
        index === 0 ? { ...row, checksum: "wrong" } : row,
      ),
      manifest,
    ),
    false,
  );
  assert.equal(
    validateMigrationLedger(rows.map((row, index) =>
      index === 0 ? { ...row, applied_at: null } : row), manifest),
    false,
  );
});

test("ledger primary key is exactly filename", () => {
  assert.equal(validateLedgerPrimaryKey([{ column_name: "filename", is_primary_key: true }]), true);
  assert.equal(validateLedgerPrimaryKey([]), false);
  assert.equal(validateLedgerPrimaryKey([{ column_name: "checksum", is_primary_key: true }]), false);
  assert.equal(validateLedgerPrimaryKey([
    { column_name: "filename", is_primary_key: true },
    { column_name: "checksum", is_primary_key: true },
  ]), false);
});

test("wrong owner, search path, ACL, and membership options fail", () => {
  assert.equal(
    validateOwnership(
      [{ object_name: "workos", owner: "workos_schema_owner" }],
      ["workos"],
      "workos_schema_owner",
    ),
    true,
  );
  assert.equal(
    validateOwnership(
      [{ object_name: "workos", owner: "workos_runtime" }],
      ["workos"],
      "workos_schema_owner",
    ),
    false,
  );

  const functions = Object.entries(SECURITY_DEFINER_MANIFEST).map(
    ([signature, searchPath]) => ({
      signature,
      owner: "workos_security_definer",
      security_definer: true,
      config: [`search_path=${searchPath}`],
    }),
  );
  assert.equal(validateSecurityDefinerFunctions(functions), true);
  assert.equal(
    validateSecurityDefinerFunctions([
      { ...functions[0], config: ["search_path=public"] },
      ...functions.slice(1),
    ]),
    false,
  );

  const aclRows = Object.entries(EXPECTED_TABLE_ACL).map(([key, privileges]) => {
    const separator = key.indexOf(":");
    return {
      role_name: key.slice(0, separator),
      object_name: key.slice(separator + 1),
      ...privileges,
    };
  });
  assert.equal(validateTableAcl(aclRows), true);
  assert.equal(
    validateTableAcl([
      { ...aclRows[0], delete: !aclRows[0].delete },
      ...aclRows.slice(1),
    ]),
    false,
  );

  const validMembershipInput = {
    rows: [
      {
        member: "workos_migrator",
        granted_role: "workos_schema_owner",
        grantor: "migration_admin",
        admin_option: false,
        inherit_option: true,
        set_option: true,
      },
    ],
    supportedColumns: [
      "member",
      "roleid",
      "grantor",
      "admin_option",
      "inherit_option",
      "set_option",
    ],
    effectiveRows: [],
    migrationIdentity: {
      can_assume_schema_owner: true,
      can_assume_security_definer: true,
    },
  };
  assert.equal(validateMemberships(validMembershipInput), true);
  assert.equal(
    validateMemberships({
      ...validMembershipInput,
      rows: [
        ...validMembershipInput.rows,
        {
          member: "workos_runtime",
          granted_role: "workos_schema_owner",
          grantor: "migration_admin",
          admin_option: false,
          inherit_option: false,
          set_option: true,
        },
      ],
    }),
    false,
  );
  assert.equal(
    validateMemberships({
      ...validMembershipInput,
      rows: [
        {
          member: "provider_external",
          granted_role: "workos_runtime",
          grantor: "migration_admin",
          admin_option: false,
          inherit_option: false,
          set_option: false,
        },
        {
          member: "workos_runtime",
          granted_role: "workos_schema_owner",
          grantor: "migration_admin",
          admin_option: false,
          inherit_option: false,
          set_option: true,
        },
        ...validMembershipInput.rows,
      ],
    }),
    false,
  );
});

test("duplicate provider identity rows permit only the usable SET graph", () => {
  const supportedColumns = [
    "member",
    "roleid",
    "grantor",
    "admin_option",
    "inherit_option",
    "set_option",
  ];
  const rows = [
    {
      member: "migration_admin",
      granted_role: "workos_schema_owner",
      grantor: "provider_admin",
      admin_option: true,
      inherit_option: false,
      set_option: false,
    },
    {
      member: "migration_admin",
      granted_role: "workos_schema_owner",
      grantor: "migration_admin",
      admin_option: false,
      inherit_option: true,
      set_option: true,
    },
    {
      member: "migration_admin",
      granted_role: "workos_security_definer",
      grantor: "provider_admin",
      admin_option: true,
      inherit_option: false,
      set_option: false,
    },
    {
      member: "migration_admin",
      granted_role: "workos_security_definer",
      grantor: "migration_admin",
      admin_option: false,
      inherit_option: true,
      set_option: true,
    },
    {
      member: "workos_migrator",
      granted_role: "workos_schema_owner",
      grantor: "migration_admin",
      admin_option: false,
      inherit_option: true,
      set_option: true,
    },
    {
      member: "provider_external",
      granted_role: "workos_runtime",
      grantor: "provider_admin",
      admin_option: true,
      inherit_option: false,
      set_option: false,
    },
  ];
  const effectiveRows = [
    { member: "migration_admin", granted_role: "workos_schema_owner", can_assume: true },
    { member: "migration_admin", granted_role: "workos_security_definer", can_assume: true },
    { member: "workos_migrator", granted_role: "workos_schema_owner", can_assume: true },
  ];
  const input = {
    rows,
    supportedColumns,
    effectiveRows,
    migrationIdentity: {
      current_user: "migration_admin",
      can_assume_schema_owner: true,
      can_assume_security_definer: true,
    },
  };
  assert.equal(validateMemberships(input), true);
  assert.equal(
    validateMemberships({
      ...input,
      effectiveRows: [
        ...effectiveRows,
        { member: "migration_admin", granted_role: "provider_pooler", can_assume: true },
      ],
    }),
    true,
  );
  assert.equal(
    validateMemberships({
      ...input,
      effectiveRows: [
        ...effectiveRows,
        { member: "migration_admin", granted_role: "workos_runtime", can_assume: true },
      ],
    }),
    false,
  );
  for (const granted_role of ["workos_worker", "workos_migrator"]) {
    assert.equal(
      validateMemberships({
        ...input,
        effectiveRows: [
          ...effectiveRows,
          { member: "migration_admin", granted_role, can_assume: true },
        ],
      }),
      false,
    );
  }
  assert.equal(
    validateMemberships({
      ...input,
      effectiveRows: effectiveRows.map((row) =>
        row.member === "workos_migrator"
          ? { ...row, can_assume: false }
          : row),
    }),
    false,
  );
  assert.equal(
    validateMemberships({
      ...input,
      effectiveRows: [
        ...effectiveRows,
        { member: "workos_runtime", granted_role: "workos_schema_owner", can_assume: true },
      ],
    }),
    false,
  );
});

test("unexpected security-definer functions fail", () => {
  const functions = Object.entries(SECURITY_DEFINER_MANIFEST).map(
    ([signature, searchPath]) => ({
      signature,
      owner: "workos_security_definer",
      security_definer: true,
      config: [`search_path=${searchPath}`],
    }),
  );
  assert.equal(validateSecurityDefinerFunctions(functions), true);
  assert.equal(
    validateSecurityDefinerFunctions([
      ...functions,
      {
        signature: "workos_security.unexpected()",
        owner: "workos_security_definer",
        security_definer: true,
        config: ["search_path=pg_catalog"],
      },
    ]),
    false,
  );
});

test("function EXECUTE allowlists are derived from migration SQL", () => {
  const manifest = [
    {
      sql: `
        GRANT EXECUTE ON FUNCTION workos_security.allowed(text)
          TO workos_runtime;
        GRANT EXECUTE ON FUNCTION workos_control.worker_only(uuid, text[])
          TO workos_worker;
      `,
    },
  ];
  const allowlists = deriveFunctionExecuteAllowlists(manifest);
  assert.deepEqual([...allowlists.workos_runtime], [
    "workos_security.allowed(text)",
  ]);
  assert.deepEqual([...allowlists.workos_worker], [
    "workos_control.worker_only(uuid,text[])",
  ]);
  assert.equal(
    validateFunctionExecute(
      [
        {
          signature: "workos_security.allowed(text)",
          runtime_execute: true,
          worker_execute: false,
        },
        {
          signature:
            "workos_control.worker_only(uuid, character varying[])",
          runtime_execute: false,
          worker_execute: false,
        },
      ],
      allowlists,
    ),
    false,
  );
});

test("unintended PUBLIC EXECUTE and public-schema CREATE fail", () => {
  assert.equal(
    validateNoPublicFunctionExecute([
      { signature: "workos_security.setting_uuid(text)", public_execute: false },
    ]),
    true,
  );
  assert.equal(
    validateNoPublicFunctionExecute([
      { signature: "workos_security.setting_uuid(text)", public_execute: true },
    ]),
    false,
  );
  assert.equal(
    validatePublicSchemaHardening({
      public_create: false,
      runtime_create: false,
      worker_create: false,
      security_definer_create: false,
      security_definer_usage: true,
    }),
    true,
  );
  assert.equal(
    validatePublicSchemaHardening({
      public_create: true,
      runtime_create: false,
      worker_create: false,
      security_definer_create: false,
      security_definer_usage: true,
    }),
    false,
  );
});

test("job-envelope trigger and control-plane privileges are exact", async () => {
  const migration = await readFile(
    new URL("../migrations/0003_stage_a_security_functions_and_rls.sql", import.meta.url),
    "utf8",
  );
  const functionStart = migration.indexOf(
    "CREATE OR REPLACE FUNCTION workos_security.prevent_job_envelope_scope_change()",
  );
  const functionEnd = migration.indexOf("\n\nCREATE TRIGGER", functionStart);
  assert.ok(functionStart >= 0 && functionEnd > functionStart);
  const canonicalFunctionDefinition = migration.slice(functionStart, functionEnd);
  const aclRows = Object.entries(EXPECTED_TABLE_ACL).map(([key, privileges]) => {
    const separator = key.indexOf(":");
    return {
      role_name: key.slice(0, separator),
      object_name: key.slice(separator + 1),
      ...privileges,
    };
  });
  aclRows.push({
    role_name: "workos_security_definer",
    object_name: "workos_control.job_envelopes",
    select: true, insert: true, update: true, delete: false, truncate: false,
    references: false, trigger: false,
  });
  const expectedWorker = new Set([
    "workos_control.claim_due_job(text,text[],integer)",
    "workos_control.finish_claimed_job(uuid,uuid,workos.job_state)",
    "workos_security.active_context_allows(uuid,uuid)",
    "workos_security.setting_uuid(text)",
    "workos_security.system_job_allows(uuid,uuid,uuid,text)",
  ]);
  const executeRows = [
    ...Object.keys(SECURITY_DEFINER_MANIFEST),
    "workos_security.setting_uuid(text)",
  ].map((signature) => ({
    signature,
    worker_execute: expectedWorker.has(normalizeSignature(signature)),
  }));
  assert.equal(
    validateJobEnvelopeControlPlane({
      triggerRows: [
        {
          trigger_name: "job_envelope_scope_immutable",
          function_signature:
            "workos_security.prevent_job_envelope_scope_change()",
          is_row: true,
          is_before: true,
          is_update: true,
          enabled: "O",
        },
      ],
      aclRows,
      executeRows,
      functionDefinitionRows: [{
        signature: "workos_security.prevent_job_envelope_scope_change()",
        function_definition: canonicalFunctionDefinition,
      }],
    }),
    true,
  );
  for (const field of ["tenant_id", "workspace_id", "job_type", "resource_id", "due_at", "dedupe_key"]) {
    const definition = `BEGIN IF ${["tenant_id", "workspace_id", "job_type", "resource_id", "due_at", "dedupe_key"]
      .filter((candidate) => candidate !== field)
      .map((candidate) => `NEW.${candidate} <> OLD.${candidate}`).join(" OR ")} THEN RAISE EXCEPTION 'immutable'; END IF; RETURN NEW; END;`;
    assert.equal(validateJobEnvelopeControlPlane({
      triggerRows: [{ trigger_name: "job_envelope_scope_immutable", function_signature: "workos_security.prevent_job_envelope_scope_change()", is_row: true, is_before: true, is_update: true, enabled: "O" }],
      aclRows, executeRows,
      functionDefinitionRows: [{ signature: "workos_security.prevent_job_envelope_scope_change()", function_definition: definition }],
    }), false);
  }
});

test("policy expressions are exact, not fragment matches", () => {
  const row = {
    policy_key: "workos.workspaces.workspace_normal_context_policy",
    command: "*", permissive: true, roles: ["PUBLIC"],
    using_expression: "workos_security.active_context_allows(tenant_id, id) OR true",
    check_expression: "workos_security.active_context_allows(tenant_id, id)",
  };
  assert.equal(validatePolicies([row]), false);
});

test("policy normalization preserves compound AND and OR grouping", () => {
  const left = normalizeExpression("A AND (B OR C)");
  const right = normalizeExpression("(A AND B) OR C");
  assert.equal(left, "aand(borc)");
  assert.equal(right, "(aandb)orc");
  assert.notEqual(left, right);
  const groupedAnd = normalizeExpression("(A OR B) AND C");
  assert.equal(groupedAnd, "(aorb)andc");
  assert.equal(normalizeExpression("A OR B AND C"), "aor(bandc)");
  assert.notEqual(groupedAnd, normalizeExpression("A OR (B AND C)"));
  assert.notEqual(groupedAnd, normalizeExpression("A OR B AND C"));
  assert.equal(
    normalizeExpression("A OR (B AND C)"),
    normalizeExpression("A OR B AND C"),
  );
  assert.equal(
    normalizeExpression("((A)) AND ((B))"),
    normalizeExpression("A AND B"),
  );
  assert.equal(
    normalizeExpression("A::text AND setting_uuid('x'::text)"),
    normalizeExpression("A AND setting_uuid('x')"),
  );
  for (const [leftExpression, rightExpression] of [
    ["x = 'NORMAL'", "x = 'normal'"],
    ["x = 'A B'", "x = 'AB'"],
    ["setting_uuid('x::text')", "setting_uuid('x')"],
    ["x = 'O''Reilly'", "x = 'OReilly'"],
  ]) {
    assert.notEqual(
      normalizeExpression(leftExpression),
      normalizeExpression(rightExpression),
    );
  }
});

test("every policy entry requires its exact canonical expression", () => {
  const expression = {
    active_context_allows: "workos_security.active_context_allows(tenant_id, workspace_id)",
    setting_uuid: "current_setting('workos.access_mode', true) = 'NORMAL' AND id = workos_security.setting_uuid('workos.user_id')",
    system_job_allows: "workos_security.system_job_allows(tenant_id, workspace_id, id, 'TASK_RECONCILE')",
  };
  const rows = EXPECTED_POLICIES.map((policy) => {
    const fragment = policy.fragment;
    let using_expression = expression[fragment];
    if (policy.key.includes("workspace_normal")) using_expression = "workos_security.active_context_allows(tenant_id, id)";
    if (policy.key.includes("tenant_normal")) using_expression = "current_setting('workos.access_mode', true) = 'NORMAL' AND id = workos_security.setting_uuid('workos.tenant_id') AND workos_security.active_context_allows(id, workos_security.setting_uuid('workos.workspace_id'))";
    if (policy.key.includes("external_identity")) using_expression = "current_setting('workos.access_mode', true) = 'NORMAL' AND user_id = workos_security.setting_uuid('workos.user_id')";
    if (policy.key.includes("portfolio_context")) using_expression = "current_setting('workos.access_mode', true) = 'ACCESS_CATALOG' AND user_id = workos_security.setting_uuid('workos.user_id')";
    if (policy.key.includes("task_system")) using_expression = expression.system_job_allows;
    if (policy.key.includes("work_object_system")) using_expression = expression.system_job_allows.replace("TASK_RECONCILE", "WORK_RECONCILE");
    if (policy.key.includes("outbox_system")) using_expression = expression.system_job_allows.replace("TASK_RECONCILE", "OUTBOX_DELIVERY");
    using_expression = using_expression
      .replace(/current_setting\('workos\.access_mode', true\)/g, "current_setting('workos.access_mode'::text, true)")
      .replace(/setting_uuid\('([^']+)'\)/g, "setting_uuid('$1'::text)")
      .split(" AND ")
      .map((term) => `(${term})`)
      .join(" AND ");
    return { policy_key: policy.key, command: policy.command, permissive: true, roles: policy.roles,
      using_expression, check_expression: policy.withCheck ? using_expression : null };
  });
  assert.equal(validatePolicies(rows), true);
  const publicPolicy = rows.find((row) => row.roles.includes("PUBLIC"));
  const workerPolicy = rows.find((row) => row.roles.includes("workos_worker"));
  assert.equal(validatePolicies(rows.map((row) =>
    row === publicPolicy ? { ...row, roles: "{PUBLIC}" } : row)), false);
  assert.equal(validatePolicies(rows.map((row) =>
    row === publicPolicy ? { ...row, roles: ["PUBLIC", "workos_worker"] } : row)), false);
  assert.equal(validatePolicies(rows.map((row) =>
    row === workerPolicy ? { ...row, roles: ["workos_worker", "workos_runtime"] } : row)), false);
  for (const row of rows) {
    assert.equal(validatePolicies(rows.map((candidate) =>
      candidate.policy_key === row.policy_key ? { ...candidate, using_expression: `${candidate.using_expression} OR true` } : candidate)), false);
  }
});

test("schema ACL contract requires usage and forbids create", () => {
  assert.doesNotMatch(
    CATALOG_QUERIES.schemaAcl,
    /has_schema_privilege\s*\(\s*['"]PUBLIC['"]/iu,
  );
  assert.match(CATALOG_QUERIES.schemaAcl, /aclexplode/iu);
  assert.match(CATALOG_QUERIES.schemaAcl, /privilege\.grantee\s*=\s*0/iu);
  assert.match(CATALOG_QUERIES.schemaAcl, /privilege\.privilege_type\s*=\s*['"]USAGE['"]/iu);
  assert.match(CATALOG_QUERIES.schemaAcl, /privilege\.privilege_type\s*=\s*['"]CREATE['"]/iu);
  const rows = ["workos", "workos_security", "workos_control"].flatMap((schema_name) =>
    ["PUBLIC", "workos_runtime", "workos_worker", "workos_security_definer"].map((role_name) => ({
      schema_name, role_name, usage: role_name !== "PUBLIC", create: false,
    })),
  );
  assert.equal(validateSchemaAcl(rows), true);
  assert.equal(validateSchemaAcl(rows.map((row) =>
    row.role_name === "PUBLIC" && row.schema_name === "workos"
      ? { ...row, usage: true }
      : row)), false);
  assert.equal(validateSchemaAcl(rows.map((row) =>
    row.role_name === "PUBLIC" && row.schema_name === "workos"
      ? { ...row, create: true }
      : row)), false);
  assert.equal(validateSchemaAcl(rows.map((row) =>
    row.role_name === "workos_worker" && row.schema_name === "workos" ? { ...row, create: true } : row)), false);
});

test("customer-zero seed requires every manifest alias", () => {
  const aliases = [
    "tenant", "workspace", "users", "memberships", "principal", "principal_user_link",
    "assignment", "assignment_principal", "action_scopes", "data_scopes",
    "foundation_work_object", "tasks", "commitment", "projection",
  ];
  const valid = Object.fromEntries(aliases.map((alias) => [alias, true]));
  assert.equal(validateCustomerZeroSeed(valid), true);
  for (const alias of aliases) {
    assert.equal(validateCustomerZeroSeed({ ...valid, [alias]: false }), false);
    const deleted = { ...valid };
    delete deleted[alias];
    assert.equal(validateCustomerZeroSeed(deleted), false);
  }
});

test("customer-zero membership SQL binds each fixed id to its role and user", () => {
  const sql = CATALOG_QUERIES.customerZeroSeed.replace(/\s+/g, " ");
  assert.match(sql, /id = '40000000-0000-4000-8000-000000000001'[^)]*user_id = '30000000-0000-4000-8000-000000000001'[^)]*role = 'OPERATOR'/);
  assert.match(sql, /id = '40000000-0000-4000-8000-000000000002'[^)]*user_id = '30000000-0000-4000-8000-000000000002'[^)]*role = 'PRINCIPAL'/);
});

test("query and connection failures produce generic secret-safe output and non-zero exit", async () => {
  const lines = [];
  const exitCode = await executeAuditCli({
    environment: {
      DATABASE_MIGRATION_URL: syntheticSecret,
      DATABASE_RUNTIME_URL: syntheticSecret,
    },
    migrationsDirectory: "/not-read",
    createClient: () => {
      throw new Error(syntheticRawError);
    },
    writeLine: (line) => lines.push(line),
  });
  assert.equal(exitCode, 1);
  assert.deepEqual(lines, ["FAIL environment_isolation"]);
  assert.equal(lines.join("\n").includes(syntheticSecret), false);
  assert.equal(lines.join("\n").includes(syntheticRawError), false);
  assert.equal(lines.every((line) => /^(PASS|FAIL) [a-z_]+$/.test(line)), true);
});

test("connection failures are generic and never expose raw errors", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "workos-audit-"));
  const lines = [];
  try {
    for (const filename of EXPECTED_MIGRATION_FILENAMES) {
      await writeFile(path.join(directory, filename), "select 1;\n");
    }
    const exitCode = await executeAuditCli({
      environment: { DATABASE_MIGRATION_URL: syntheticSecret },
      migrationsDirectory: directory,
      createClient: () => ({
        connect: async () => {
          throw new Error(syntheticRawError);
        },
        end: async () => {},
      }),
      writeLine: (line) => lines.push(line),
    });
    assert.equal(exitCode, 1);
    assert.deepEqual(lines, [
      "PASS environment_isolation",
      "PASS migration_manifest",
      "FAIL connection",
    ]);
    assert.equal(lines.join("\n").includes(syntheticSecret), false);
    assert.equal(lines.join("\n").includes(syntheticRawError), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("query failures are generic, roll back, close, and exit non-zero", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "workos-audit-"));
  const lines = [];
  const commands = [];
  try {
    for (const filename of EXPECTED_MIGRATION_FILENAMES) {
      await writeFile(path.join(directory, filename), "select 1;\n");
    }
    const exitCode = await executeAuditCli({
      environment: { DATABASE_MIGRATION_URL: syntheticSecret },
      migrationsDirectory: directory,
      createClient: () => ({
        connect: async () => {},
        query: async (sql) => {
          commands.push(sql);
          if (sql.startsWith("BEGIN")) return { rows: [] };
          if (sql === "ROLLBACK") return { rows: [] };
          throw new Error(syntheticRawError);
        },
        end: async () => {
          commands.push("END");
        },
      }),
      writeLine: (line) => lines.push(line),
    });
    assert.equal(exitCode, 1);
    assert.deepEqual(lines, [
      "PASS environment_isolation",
      "PASS migration_manifest",
      "FAIL query_error",
    ]);
    assert.equal(commands[0].startsWith("BEGIN TRANSACTION"), true);
    assert.equal(commands.includes("ROLLBACK"), true);
    assert.equal(commands.at(-1), "END");
    assert.equal(lines.join("\n").includes(syntheticSecret), false);
    assert.equal(lines.join("\n").includes(syntheticRawError), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("safe output never serializes arbitrary errors or values", () => {
  assert.equal(safeResultLine(false, syntheticRawError), "FAIL query_error");
  assert.equal(safeResultLine(true, "migration_manifest"), "PASS migration_manifest");
});

test("catalog query manifest is SELECT-only", () => {
  assert.equal(assertReadOnlyQueryManifest(), true);
  assert.match(
    CATALOG_QUERIES.policies,
    /when role_oid = 0 then 'PUBLIC'::text\s+else role\.rolname::text\s+end/,
  );
  assert.equal(
    assertReadOnlyQueryManifest({ bad: "delete from workos.tasks" }),
    false,
  );
});

test("ledger primary-key query uses safe aliases and remains read-only", () => {
  const query = CATALOG_QUERIES.ledgerPrimaryKey;
  assert.match(query, /from pg_constraint as migration_constraint/);
  assert.match(
    query,
    /as key_column\(attnum, ordinal_position\)/,
  );
  assert.match(query, /order by key_column\.ordinal_position/);
  assert.doesNotMatch(query, /\bpg_constraint\s+constraint\b/);
  assert.equal(
    assertReadOnlyQueryManifest({ ledgerPrimaryKey: query }),
    true,
  );
});

test("generated effective-membership query is read-only", () => {
  const query = effectiveMembershipQuery([
    "member",
    "roleid",
    "admin_option",
    "set_option",
  ]);
  assert.equal(assertReadOnlyQueryManifest({ effectiveMembershipQuery: query }), true);
});

test("write-capable generated query is rejected before client.query", async () => {
  let calls = 0;
  const client = {
    query: async () => {
      calls += 1;
      return { rows: [] };
    },
  };
  await assert.rejects(
    () => safeQuery(client, "UPDATE workos.tasks SET status = 'DONE'"),
    (error) => error instanceof AuditInvariantError && error.invariant === "query_error",
  );
  assert.equal(calls, 0);
});
