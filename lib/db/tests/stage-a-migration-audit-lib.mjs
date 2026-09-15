import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

export const EXPECTED_MIGRATION_FILENAMES = Object.freeze([
  "0001_stage_a_roles_and_schemas.sql",
  "0002_stage_a_tables.sql",
  "0003_stage_a_security_functions_and_rls.sql",
  "0004_stage_a_customer_zero_seed.sql",
  "0005_stage_a_security_definer_ownership.sql",
  "0006_stage_a_function_hardening.sql",
  "0007_stage_a_worker_policy_grants.sql",
  "0008_stage_a_external_login_guards.sql",
]);

export const INVARIANT_NAMES = Object.freeze([
  "environment_isolation",
  "migration_manifest",
  "transaction_read_only",
  "migration_identity",
  "role_attributes",
  "role_memberships",
  "migration_ledger_schema",
  "migration_ledger_rows",
  "schema_ownership",
  "table_ownership",
  "rls_enforcement",
  "policy_manifest",
  "security_definer_manifest",
  "setting_uuid_security_invoker",
  "function_execute_allowlist",
  "public_function_execute",
  "public_schema_hardening",
  "table_acl_manifest",
  "append_only_boundaries",
  "job_envelope_control_plane",
  "customer_zero_seed",
]);

export const CANONICAL_ROLES = Object.freeze({
  workos_schema_owner: {
    rolcanlogin: false,
    rolsuper: false,
    rolcreatedb: false,
    rolcreaterole: false,
    rolinherit: false,
    rolbypassrls: false,
    rolreplication: false,
  },
  workos_migrator: {
    rolcanlogin: false,
    rolsuper: false,
    rolcreatedb: false,
    rolcreaterole: false,
    rolinherit: false,
    rolbypassrls: false,
    rolreplication: false,
  },
  workos_runtime: {
    rolcanlogin: true,
    rolsuper: false,
    rolcreatedb: false,
    rolcreaterole: false,
    rolinherit: false,
    rolbypassrls: false,
    rolreplication: false,
  },
  workos_worker: {
    rolcanlogin: true,
    rolsuper: false,
    rolcreatedb: false,
    rolcreaterole: false,
    rolinherit: false,
    rolbypassrls: false,
    rolreplication: false,
  },
  workos_security_definer: {
    rolcanlogin: false,
    rolsuper: false,
    rolcreatedb: false,
    rolcreaterole: false,
    rolinherit: false,
    rolbypassrls: true,
    rolreplication: false,
  },
});

export const WORKOS_TABLES = Object.freeze([
  "workos.activity_events",
  "workos.audit_records",
  "workos.commitments",
  "workos.effect_instances",
  "workos.execution_guards",
  "workos.external_identities",
  "workos.job_claim_events",
  "workos.operator_assignment_action_scopes",
  "workos.operator_assignment_data_scopes",
  "workos.operator_assignment_principals",
  "workos.operator_assignments",
  "workos.portfolio_context_assignments",
  "workos.portfolio_contexts",
  "workos.portfolio_metadata_projection",
  "workos.principal_user_links",
  "workos.principals",
  "workos.task_executor_assignments",
  "workos.tasks",
  "workos.tenants",
  "workos.users",
  "workos.work_objects",
  "workos.work_state_transitions",
  "workos.workspaces",
  "workos.outbox_messages",
  "workos.workspace_memberships",
]);

export const OWNED_TABLES = Object.freeze([
  ...WORKOS_TABLES,
  "workos_control.job_envelopes",
].sort());

const NORMAL_CONTEXT_POLICY_TABLES = Object.freeze([
  "workspace_memberships",
  "principals",
  "principal_user_links",
  "operator_assignments",
  "operator_assignment_principals",
  "operator_assignment_action_scopes",
  "operator_assignment_data_scopes",
  "portfolio_metadata_projection",
  "work_objects",
  "tasks",
  "task_executor_assignments",
  "commitments",
  "activity_events",
  "audit_records",
  "work_state_transitions",
  "outbox_messages",
  "effect_instances",
  "execution_guards",
  "job_claim_events",
]);

export const EXPECTED_POLICIES = Object.freeze([
  ...NORMAL_CONTEXT_POLICY_TABLES.map((table) => ({
    key: `workos.${table}.normal_context_policy`,
    command: "*",
    roles: ["PUBLIC"],
    using: true,
    withCheck: true,
    fragment: "active_context_allows",
  })),
  {
    key: "workos.workspaces.workspace_normal_context_policy",
    command: "*",
    roles: ["PUBLIC"],
    using: true,
    withCheck: true,
    fragment: "active_context_allows",
  },
  {
    key: "workos.tenants.tenant_normal_context_policy",
    command: "*",
    roles: ["PUBLIC"],
    using: true,
    withCheck: false,
    fragment: "active_context_allows",
  },
  {
    key: "workos.users.user_self_policy",
    command: "*",
    roles: ["PUBLIC"],
    using: true,
    withCheck: false,
    fragment: "setting_uuid",
  },
  {
    key: "workos.external_identities.external_identity_self_policy",
    command: "*",
    roles: ["PUBLIC"],
    using: true,
    withCheck: false,
    fragment: "setting_uuid",
  },
  {
    key: "workos.portfolio_contexts.portfolio_context_self_policy",
    command: "*",
    roles: ["PUBLIC"],
    using: true,
    withCheck: true,
    fragment: "setting_uuid",
  },
  {
    key: "workos.tasks.task_system_job_policy",
    command: "*",
    roles: ["workos_worker"],
    using: true,
    withCheck: true,
    fragment: "system_job_allows",
  },
  {
    key: "workos.work_objects.work_object_system_job_policy",
    command: "*",
    roles: ["workos_worker"],
    using: true,
    withCheck: true,
    fragment: "system_job_allows",
  },
  {
    key: "workos.outbox_messages.outbox_system_job_policy",
    command: "r",
    roles: ["workos_worker"],
    using: true,
    withCheck: false,
    fragment: "system_job_allows",
  },
]);

const POLICY_EXPRESSIONS = Object.freeze({
  active: "workos_security.active_context_allows(tenant_id, workspace_id)",
  workspace: "workos_security.active_context_allows(tenant_id, id)",
  tenant: "current_setting('workos.access_mode', true) = 'NORMAL' AND id = workos_security.setting_uuid('workos.tenant_id') AND workos_security.active_context_allows(id, workos_security.setting_uuid('workos.workspace_id'))",
  user: "current_setting('workos.access_mode', true) = 'NORMAL' AND id = workos_security.setting_uuid('workos.user_id')",
  external: "current_setting('workos.access_mode', true) = 'NORMAL' AND user_id = workos_security.setting_uuid('workos.user_id')",
  portfolio: "current_setting('workos.access_mode', true) = 'ACCESS_CATALOG' AND user_id = workos_security.setting_uuid('workos.user_id')",
  systemTask: "workos_security.system_job_allows(tenant_id, workspace_id, id, 'TASK_RECONCILE')",
  systemWork: "workos_security.system_job_allows(tenant_id, workspace_id, id, 'WORK_RECONCILE')",
  systemOutbox: "workos_security.system_job_allows(tenant_id, workspace_id, id, 'OUTBOX_DELIVERY')",
});
export function normalizeExpression(value) {
  const source = String(value ?? "");
  const segments = [];
  let outside = "";
  const flushOutside = () => {
    if (outside === "") return;
    segments.push(
      outside
        .toLowerCase()
        .replace(/::\s*(?:pg_catalog\.)?(?:text|uuid|name|character varying|bool|boolean)\b/g, "")
        .replace(/\b(?:text|uuid|name|character varying|boolean)\s*\(/g, "("),
    );
    outside = "";
  };

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (character === "'" || character === '"') {
      flushOutside();
      const quote = character;
      const start = index;
      index += 1;
      while (index < source.length) {
        if (source[index] === "\\" && index + 1 < source.length) {
          index += 2;
          continue;
        }
        if (source[index] === quote) {
          if (source[index + 1] === quote) {
            index += 2;
            continue;
          }
          index += 1;
          break;
        }
        index += 1;
      }
      segments.push(source.slice(start, index));
      index -= 1;
    } else if (character === "-" && source[index + 1] === "-") {
      outside += " ";
      index += 2;
      while (index < source.length && source[index] !== "\n") index += 1;
      index -= 1;
    } else if (character === "/" && source[index + 1] === "*") {
      outside += " ";
      index += 2;
      while (
        index + 1 < source.length &&
        !(source[index] === "*" && source[index + 1] === "/")
      ) {
        index += 1;
      }
      index += 1;
    } else {
      outside += character;
    }
  }
  flushOutside();
  const expression = segments.join("");

  function compactOutsideWhitespace(input) {
    const compacted = [];
    let quote = null;
    for (let index = 0; index < input.length; index += 1) {
      const character = input[index];
      if (quote) {
        compacted.push(character);
        if (character === "\\" && index + 1 < input.length) {
          compacted.push(input[index + 1]);
          index += 1;
        } else if (character === quote) {
          if (input[index + 1] === quote) {
            compacted.push(input[index + 1]);
            index += 1;
          } else {
            quote = null;
          }
        }
      } else if (character === "'" || character === '"') {
        quote = character;
        compacted.push(character);
      } else if (!/\s/u.test(character)) {
        compacted.push(character);
      }
    }
    return compacted.join("");
  }

  function matchingOuterParentheses(input) {
    if (!input.startsWith("(")) return false;
    let depth = 0;
    let quote = null;
    for (let index = 0; index < input.length; index += 1) {
      const character = input[index];
      if (quote) {
        if (character === "\\" && index + 1 < input.length) {
          index += 1;
          continue;
        }
        if (character === quote) {
          if (input[index + 1] === quote) {
            index += 1;
          } else {
            quote = null;
          }
        }
        continue;
      }
      if (character === "'" || character === '"') {
        quote = character;
      } else if (character === "(") {
        depth += 1;
      } else if (character === ")" && --depth === 0) {
        return index === input.length - 1;
      }
    }
    return false;
  }

  function splitBoolean(input, operator) {
    const parts = [];
    let start = 0;
    let depth = 0;
    let quote = null;
    for (let index = 0; index < input.length; index += 1) {
      const character = input[index];
      if (quote) {
        if (character === "\\" && index + 1 < input.length) {
          index += 1;
          continue;
        }
        if (character === quote) {
          if (input[index + 1] === quote) {
            index += 1;
          } else {
            quote = null;
          }
        }
        continue;
      }
      if (character === "'" || character === '"') {
        quote = character;
        continue;
      }
      if (character === "(") {
        depth += 1;
        continue;
      }
      if (character === ")") {
        depth -= 1;
        continue;
      }
      if (
        depth === 0 &&
        input.startsWith(operator, index) &&
        !/[a-z0-9_$]/u.test(input[index - 1] ?? "") &&
        !/[a-z0-9_$]/u.test(input[index + operator.length] ?? "")
      ) {
        parts.push(input.slice(start, index));
        start = index + operator.length;
        index += operator.length - 1;
      }
    }
    if (parts.length === 0) return [input];
    parts.push(input.slice(start));
    return parts;
  }

  function normalizeBoolean(input) {
    let valueToNormalize = input.trim();
    while (matchingOuterParentheses(valueToNormalize)) {
      valueToNormalize = valueToNormalize.slice(1, -1).trim();
    }
    const orParts = splitBoolean(valueToNormalize, "or");
    if (orParts.length > 1) {
      const children = orParts.map((part) => normalizeBoolean(part));
      return {
        kind: "or",
        text: children
          .map((child) => child.kind === "and" ? `(${child.text})` : child.text)
          .join("or"),
      };
    }
    const andParts = splitBoolean(valueToNormalize, "and");
    if (andParts.length > 1) {
      const children = andParts.map((part) => normalizeBoolean(part));
      return {
        kind: "and",
        text: children
          .map((child) => child.kind === "or" ? `(${child.text})` : child.text)
          .join("and"),
      };
    }
    return { kind: "atom", text: valueToNormalize };
  }

  return compactOutsideWhitespace(normalizeBoolean(expression).text);
}
function expectedPolicyExpressions(policy) {
  const key = policy.key;
  if (key.includes("workspace_normal")) return [POLICY_EXPRESSIONS.workspace, POLICY_EXPRESSIONS.workspace];
  if (key.includes("tenant_normal")) return [POLICY_EXPRESSIONS.tenant, null];
  if (key.includes("user_self")) return [POLICY_EXPRESSIONS.user, null];
  if (key.includes("external_identity")) return [POLICY_EXPRESSIONS.external, null];
  if (key.includes("portfolio_context_self")) return [POLICY_EXPRESSIONS.portfolio, POLICY_EXPRESSIONS.portfolio];
  if (key.includes("task_system")) return [POLICY_EXPRESSIONS.systemTask, POLICY_EXPRESSIONS.systemTask];
  if (key.includes("work_object_system")) return [POLICY_EXPRESSIONS.systemWork, POLICY_EXPRESSIONS.systemWork];
  if (key.includes("outbox_system")) return [POLICY_EXPRESSIONS.systemOutbox, null];
  return [POLICY_EXPRESSIONS.active, POLICY_EXPRESSIONS.active];
}

export const SECURITY_DEFINER_MANIFEST = Object.freeze({
  "workos_security.active_context_allows(uuid,uuid)": "pg_catalog,workos",
  "workos_security.system_job_allows(uuid,uuid,uuid,text)":
    "pg_catalog,workos_control",
  "workos_security.get_access_catalog_for_current_user()":
    "pg_catalog,workos",
  "workos_security.open_portfolio_context(text)": "pg_catalog,workos,public",
  "workos_security.get_portfolio_metadata(uuid)": "pg_catalog,workos",
  "workos_control.enqueue_job(text,uuid,timestamptz,text)":
    "pg_catalog,workos_control",
  "workos_control.claim_due_job(text,text[],integer)":
    "pg_catalog,workos_control,workos,public",
  "workos_control.finish_claimed_job(uuid,uuid,workos.job_state)":
    "pg_catalog,workos_control,workos,public",
  "workos_security.prevent_job_envelope_scope_change()": "pg_catalog",
});

const TABLE_PRIVILEGES = Object.freeze([
  "select",
  "insert",
  "update",
  "delete",
  "truncate",
  "references",
  "trigger",
]);

function privileges(...values) {
  return Object.fromEntries(
    TABLE_PRIVILEGES.map((privilege) => [
      privilege,
      values.includes(privilege),
    ]),
  );
}

const RUNTIME_SELECT_INSERT_UPDATE = [
  "workos.workspaces",
  "workos.workspace_memberships",
  "workos.principals",
  "workos.principal_user_links",
  "workos.operator_assignments",
  "workos.operator_assignment_principals",
  "workos.operator_assignment_action_scopes",
  "workos.operator_assignment_data_scopes",
  "workos.portfolio_metadata_projection",
  "workos.work_objects",
  "workos.tasks",
  "workos.task_executor_assignments",
  "workos.commitments",
  "workos.execution_guards",
];

const RUNTIME_SELECT = [
  "workos.tenants",
  "workos.users",
  "workos.external_identities",
];

const RUNTIME_SELECT_INSERT = [
  "workos.activity_events",
  "workos.audit_records",
  "workos.work_state_transitions",
  "workos.outbox_messages",
  "workos.effect_instances",
  "workos.job_claim_events",
  "workos.portfolio_contexts",
  "workos.portfolio_context_assignments",
];

const WORKER_SELECT_UPDATE = [
  "workos.tasks",
  "workos.work_objects",
  "workos.execution_guards",
];

const WORKER_SELECT = ["workos.outbox_messages"];

const WORKER_INSERT = [
  "workos.activity_events",
  "workos.audit_records",
  "workos.work_state_transitions",
  "workos.job_claim_events",
];

export const EXPECTED_TABLE_ACL = Object.freeze(
  Object.fromEntries(
    ["workos_runtime", "workos_worker"].flatMap((role) =>
      OWNED_TABLES.map((table) => {
        let expected = privileges();
        if (role === "workos_runtime") {
          if (RUNTIME_SELECT_INSERT_UPDATE.includes(table)) {
            expected = privileges("select", "insert", "update");
          } else if (RUNTIME_SELECT.includes(table)) {
            expected = privileges("select");
          } else if (RUNTIME_SELECT_INSERT.includes(table)) {
            expected = privileges("select", "insert");
          }
        } else if (WORKER_SELECT_UPDATE.includes(table)) {
          expected = privileges("select", "update");
        } else if (WORKER_SELECT.includes(table)) {
          expected = privileges("select");
        } else if (WORKER_INSERT.includes(table)) {
          expected = privileges("insert");
        }
        return [`${role}:${table}`, expected];
      }),
    ),
  ),
);

export class AuditInvariantError extends Error {
  constructor(invariant) {
    super(invariant);
    this.name = "AuditInvariantError";
    this.invariant = invariant;
  }
}

export class AuditQueryError extends Error {
  constructor() {
    super("query_error");
    this.name = "AuditQueryError";
  }
}

function hasOwn(environment, name) {
  return Object.prototype.hasOwnProperty.call(environment, name);
}

export function requireMigrationEnvironment(environment) {
  if (
    hasOwn(environment, "DATABASE_RUNTIME_URL") ||
    hasOwn(environment, "DATABASE_WORKER_URL")
  ) {
    throw new AuditInvariantError("environment_isolation");
  }

  const migrationUrl = environment.DATABASE_MIGRATION_URL;
  if (typeof migrationUrl !== "string" || migrationUrl.trim() === "") {
    throw new AuditInvariantError("environment_isolation");
  }

  return migrationUrl;
}

export async function loadMigrationManifest(migrationsDirectory) {
  const filenames = (await readdir(migrationsDirectory))
    .filter((filename) => filename.endsWith(".sql"))
    .sort();

  if (!sameStringSet(filenames, EXPECTED_MIGRATION_FILENAMES)) {
    throw new AuditInvariantError("migration_manifest");
  }

  return Promise.all(
    filenames.map(async (filename) => {
      const sql = await readFile(path.join(migrationsDirectory, filename), "utf8");
      return {
        filename,
        checksum: createHash("sha256").update(sql).digest("hex"),
        sql,
      };
    }),
  );
}

function normalizeType(type) {
  return type
    .trim()
    .toLowerCase()
    .replace(/\btimestamp with time zone\b/g, "timestamptz")
    .replace(/\btimestamp without time zone\b/g, "timestamp")
    .replace(/\s+/g, "");
}

export function normalizeSignature(signature) {
  const match = signature
    .trim()
    .match(/^([a-z_][a-z0-9_$]*\.[a-z_][a-z0-9_$]*)\((.*)\)$/i);
  if (!match) return signature.trim().toLowerCase().replace(/\s+/g, "");
  const [, name, argumentsText] = match;
  const argumentsList =
    argumentsText.trim() === ""
      ? []
      : argumentsText.split(",").map((value) => normalizeType(value));
  return `${name.toLowerCase()}(${argumentsList.join(",")})`;
}

export function deriveFunctionExecuteAllowlists(migrationManifest) {
  const allowlists = {
    workos_runtime: new Set(),
    workos_worker: new Set(),
  };
  const grantPattern =
    /GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+([a-z_][a-z0-9_$]*\.[a-z_][a-z0-9_$]*\s*\([^;]*?\))\s+TO\s+([^;]+);/giu;

  for (const migration of migrationManifest) {
    for (const match of migration.sql.matchAll(grantPattern)) {
      const signature = normalizeSignature(match[1]);
      const roles = match[2]
        .split(",")
        .map((role) => role.trim().toLowerCase());
      for (const role of roles) {
        allowlists[role]?.add(signature);
      }
    }
  }
  return allowlists;
}

function sameStringSet(actual, expected) {
  const left = [...actual].sort();
  const right = [...expected].sort();
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function normalizeBoolean(value) {
  return value === true || value === "t" || value === "true";
}

export function validateMigrationLedger(rows, migrationManifest) {
  const expected = new Map(
    migrationManifest.map(({ filename, checksum }) => [filename, checksum]),
  );
  if (rows.length !== expected.size) return false;
  const filenames = rows.map((row) => row.filename);
  if (new Set(filenames).size !== expected.size || !sameStringSet(filenames, [...expected.keys()])) return false;
  return rows.every(
    (row) =>
      expected.get(row.filename) === row.checksum &&
      row.applied_at !== null &&
      row.applied_at !== undefined,
  );
}

export function validateRoleAttributes(rows) {
  if (rows.length !== Object.keys(CANONICAL_ROLES).length) return false;
  const actual = new Map(rows.map((row) => [row.rolname, row]));
  return Object.entries(CANONICAL_ROLES).every(([role, attributes]) => {
    const row = actual.get(role);
    return (
      row &&
      Object.entries(attributes).every(
        ([attribute, expected]) =>
          normalizeBoolean(row[attribute]) === expected,
      )
    );
  });
}

export function validateMemberships({
  rows,
  supportedColumns,
  effectiveRows,
  migrationIdentity,
}) {
  const supportsOptions =
    supportedColumns.includes("inherit_option") &&
    supportedColumns.includes("set_option");

  for (const row of rows) {
    if (
      typeof row.grantor !== "string" ||
      row.grantor.length === 0 ||
      row.admin_option === null ||
      row.admin_option === undefined ||
      (supportsOptions &&
        (row.inherit_option === null ||
          row.inherit_option === undefined ||
          row.set_option === null ||
          row.set_option === undefined))
    ) {
      return false;
    }

    const canonicalMembership =
      row.member === "workos_migrator" &&
      row.granted_role === "workos_schema_owner";
    const intentionalIdentityGrant =
      row.member === migrationIdentity.current_user &&
      ["workos_schema_owner", "workos_security_definer"].includes(row.granted_role);
    if (Object.hasOwn(CANONICAL_ROLES, row.granted_role) &&
        !canonicalMembership && !intentionalIdentityGrant &&
        !(["workos_runtime", "workos_worker", "workos_migrator"].includes(row.granted_role) &&
          !Object.hasOwn(CANONICAL_ROLES, row.member))) {
      return false;
    }
    if (Object.hasOwn(CANONICAL_ROLES, row.member) && !intentionalIdentityGrant) {
      if (!canonicalMembership) return false;
      if (normalizeBoolean(row.admin_option) || !supportsOptions ||
          !normalizeBoolean(row.set_option)) return false;
    }
    if (intentionalIdentityGrant) {
      if (!supportsOptions) return false;
      const isInertProviderGrant =
        !normalizeBoolean(row.inherit_option) &&
        !normalizeBoolean(row.set_option);
      if (
        !isInertProviderGrant &&
        (normalizeBoolean(row.admin_option) || !normalizeBoolean(row.set_option))
      ) {
        return false;
      }
    }

    const providerManagedApplicationGrant =
      ["workos_runtime", "workos_worker", "workos_migrator"].includes(
        row.granted_role,
      ) &&
      !Object.hasOwn(CANONICAL_ROLES, row.member);
    if (providerManagedApplicationGrant && (!supportsOptions ||
        normalizeBoolean(row.inherit_option) || normalizeBoolean(row.set_option))) {
      return false;
    }
  }

  if (
    effectiveRows.some(
      (row) =>
        ["workos_runtime", "workos_worker"].includes(row.member) &&
        normalizeBoolean(row.can_assume),
    )
  ) {
    return false;
  }

  const migratorSchemaOwner = rows.find(
    (row) =>
      row.member === "workos_migrator" &&
      row.granted_role === "workos_schema_owner",
  );
  if (!migratorSchemaOwner || !supportsOptions) return false;
  if (normalizeBoolean(migratorSchemaOwner.admin_option)) return false;
  if (supportsOptions && !normalizeBoolean(migratorSchemaOwner.set_option)) {
    return false;
  }

  const identityName = migrationIdentity.current_user;
  if (typeof identityName === "string" && identityName.length > 0) {
    const identityEffectiveTargets = effectiveRows
      .filter(
        (row) =>
          row.member === identityName && normalizeBoolean(row.can_assume),
      )
      .map((row) => row.granted_role);
    if (
      !sameStringSet(identityEffectiveTargets, [
        "workos_schema_owner",
        "workos_security_definer",
      ]) ||
      !migrationIdentity.can_assume_schema_owner ||
      !migrationIdentity.can_assume_security_definer
    ) {
      return false;
    }
    const migratorEffective = effectiveRows.find(
      (row) =>
        row.member === "workos_migrator" &&
        row.granted_role === "workos_schema_owner" &&
        normalizeBoolean(row.can_assume),
    );
    if (!migratorEffective) return false;
  }

  return (
    migrationIdentity.can_assume_schema_owner &&
    migrationIdentity.can_assume_security_definer
  );
}

export function validateMigrationIdentity(row) {
  return Boolean(
    row &&
      row.session_user === row.current_user &&
      !["workos_runtime", "workos_worker"].includes(row.current_user) &&
      normalizeBoolean(row.rolcanlogin) &&
      !normalizeBoolean(row.rolsuper) &&
      normalizeBoolean(row.rolcreaterole) &&
      normalizeBoolean(row.can_assume_schema_owner) &&
      normalizeBoolean(row.can_assume_security_definer),
  );
}

export function validateLedgerSchema(rows) {
  const expected = [
    {
      column_name: "filename",
      data_type: "text",
      is_nullable: "NO",
      has_default: false,
    },
    {
      column_name: "checksum",
      data_type: "text",
      is_nullable: "NO",
      has_default: false,
    },
    {
      column_name: "applied_at",
      data_type: "timestamp with time zone",
      is_nullable: "NO",
      has_default: true,
    },
  ];
  if (rows.length !== expected.length) return false;
  return expected.every((wanted) =>
    rows.some(
      (row) =>
        row.column_name === wanted.column_name &&
        row.data_type === wanted.data_type &&
        row.is_nullable === wanted.is_nullable &&
        Boolean(row.column_default) === wanted.has_default,
    ),
  );
}

export function validateLedgerPrimaryKey(rows) {
  return rows.length === 1 &&
    rows[0].column_name === "filename" &&
    normalizeBoolean(rows[0].is_primary_key);
}

export function validateOwnership(rows, expectedObjects, expectedOwner) {
  if (rows.length !== expectedObjects.length) return false;
  const actual = new Map(rows.map((row) => [row.object_name, row.owner]));
  return expectedObjects.every(
    (objectName) => actual.get(objectName) === expectedOwner,
  );
}

export function validateRls(rows) {
  if (rows.length !== WORKOS_TABLES.length) return false;
  const expected = new Set(WORKOS_TABLES);
  return rows.every(
    (row) =>
      expected.has(row.object_name) &&
      normalizeBoolean(row.relrowsecurity) &&
      normalizeBoolean(row.relforcerowsecurity),
  );
}

export function validatePolicies(rows) {
  if (rows.length !== EXPECTED_POLICIES.length) return false;
  const actual = new Map(rows.map((row) => [row.policy_key, row]));
  return EXPECTED_POLICIES.every((expected) => {
    const row = actual.get(expected.key);
    const roles = Array.isArray(row?.roles) ? row.roles : [];
    const [using, check] = expectedPolicyExpressions(expected);
    return Boolean(
      row &&
        row.command === expected.command &&
        normalizeBoolean(row.permissive) &&
        sameStringSet(roles, expected.roles) &&
        Boolean(row.using_expression) === expected.using &&
        Boolean(row.check_expression) === expected.withCheck &&
        normalizeExpression(row.using_expression) === normalizeExpression(using) &&
        normalizeExpression(row.check_expression) === normalizeExpression(check),
    );
  });
}

function normalizeSearchPath(config) {
  const settings = Array.isArray(config) ? config : [];
  const searchPath = settings.find((entry) => entry.startsWith("search_path="));
  return searchPath
    ? searchPath.slice("search_path=".length).replace(/\s+/g, "")
    : "";
}

export function validateSecurityDefinerFunctions(rows) {
  const securityDefiners = rows.filter((row) => normalizeBoolean(row.security_definer));
  const expectedSignatures = Object.keys(SECURITY_DEFINER_MANIFEST);
  if (securityDefiners.length !== expectedSignatures.length) return false;
  const actual = new Map(
    securityDefiners.map((row) => [normalizeSignature(row.signature), row]),
  );
  return expectedSignatures.every((signature) => {
    const row = actual.get(signature);
    return Boolean(
      row &&
        row.owner === "workos_security_definer" &&
        normalizeSearchPath(row.config) ===
          SECURITY_DEFINER_MANIFEST[signature].replace(/\s+/g, ""),
    );
  });
}

export function validateSettingUuidInvoker(rows) {
  const settingUuid = rows.find(
    (row) =>
      normalizeSignature(row.signature) ===
      "workos_security.setting_uuid(text)",
  );
  return Boolean(settingUuid && !normalizeBoolean(settingUuid.security_definer));
}

export function validateFunctionExecute(rows, allowlists) {
  const signatures = new Set(
    rows.map((row) => normalizeSignature(row.signature)),
  );
  const allExpectedFunctionsExist = [
    ...allowlists.workos_runtime,
    ...allowlists.workos_worker,
  ].every((signature) => signatures.has(signature));
  if (!allExpectedFunctionsExist) return false;

  return rows.every((row) => {
    const signature = normalizeSignature(row.signature);
    return (
      normalizeBoolean(row.runtime_execute) ===
        allowlists.workos_runtime.has(signature) &&
      normalizeBoolean(row.worker_execute) ===
        allowlists.workos_worker.has(signature)
    );
  });
}

export function validateNoPublicFunctionExecute(rows) {
  return rows.every((row) => !normalizeBoolean(row.public_execute));
}

export function validatePublicSchemaHardening(row) {
  return Boolean(
    row &&
      !normalizeBoolean(row.public_create) &&
      !normalizeBoolean(row.runtime_create) &&
      !normalizeBoolean(row.worker_create) &&
      !normalizeBoolean(row.security_definer_create) &&
      normalizeBoolean(row.security_definer_usage),
  );
}

export function validateSchemaAcl(rows) {
  const expected = new Map([
    ["workos", ["workos_runtime", "workos_worker", "workos_security_definer"]],
    ["workos_security", ["workos_runtime", "workos_worker", "workos_security_definer"]],
    ["workos_control", ["workos_runtime", "workos_worker", "workos_security_definer"]],
  ]);
  if (rows.length !== 12) return false;
  const actual = new Map(rows.map((row) => [`${row.schema_name}:${row.role_name}`, row]));
  if (actual.size !== 12) return false;
  return [...expected].every(([schema, roles]) =>
    [...roles, "PUBLIC"].every((role) => {
      const row = actual.get(`${schema}:${role}`);
      const expectedUsage = role !== "PUBLIC";
      return row &&
        normalizeBoolean(row.usage) === expectedUsage &&
        !normalizeBoolean(row.create);
    }),
  );
}

export function validateTableAcl(rows) {
  if (rows.length !== Object.keys(EXPECTED_TABLE_ACL).length) return false;
  const actual = new Map(
    rows.map((row) => [`${row.role_name}:${row.object_name}`, row]),
  );
  return Object.entries(EXPECTED_TABLE_ACL).every(([key, expected]) => {
    const row = actual.get(key);
    return Boolean(
      row &&
        TABLE_PRIVILEGES.every(
          (privilege) =>
            normalizeBoolean(row[privilege]) === expected[privilege],
        ),
    );
  });
}

export function validateAppendOnlyBoundaries(rows) {
  const appendOnlyTables = new Set([
    "workos.activity_events",
    "workos.audit_records",
    "workos.work_state_transitions",
    "workos.job_claim_events",
  ]);
  return rows
    .filter((row) => appendOnlyTables.has(row.object_name))
    .every(
      (row) =>
        !normalizeBoolean(row.update) && !normalizeBoolean(row.delete),
    );
}

export function validateJobEnvelopeControlPlane({ triggerRows, aclRows, executeRows, functionDefinitionRows = [] }) {
  const trigger = triggerRows[0];
  if (
    triggerRows.length !== 1 ||
    !trigger ||
    trigger.trigger_name !== "job_envelope_scope_immutable" ||
    normalizeSignature(trigger.function_signature) !==
      "workos_security.prevent_job_envelope_scope_change()" ||
    !normalizeBoolean(trigger.is_row) ||
    !normalizeBoolean(trigger.is_before) ||
    !normalizeBoolean(trigger.is_update) ||
    trigger.enabled !== "O"
  ) {
    return false;
  }

  const jobAclRows = aclRows.filter(
    (row) => row.object_name === "workos_control.job_envelopes",
  );
  if (jobAclRows.length !== 3) return false;
  if (new Set(jobAclRows.map((row) => row.role_name)).size !== 3 ||
      !["workos_runtime", "workos_worker", "workos_security_definer"].every(
        (role) => jobAclRows.some((row) => row.role_name === role),
      )) return false;
  const securityAcl = jobAclRows.find((row) => row.role_name === "workos_security_definer");
  const appAcls = jobAclRows.filter((row) => ["workos_runtime", "workos_worker"].includes(row.role_name));
  if (!securityAcl || !["select", "insert", "update"].every((p) => normalizeBoolean(securityAcl[p])) ||
      ["delete", "truncate", "references", "trigger"].some((p) => normalizeBoolean(securityAcl[p])) ||
      appAcls.some((row) => TABLE_PRIVILEGES.some((privilege) => normalizeBoolean(row[privilege])))) {
    return false;
  }
  if (functionDefinitionRows.length !== 1) {
    return false;
  }
  {
    const definition = functionDefinitionRows.find((row) =>
      normalizeSignature(row.signature) === "workos_security.prevent_job_envelope_scope_change()");
    if (!definition) return false;
    const body = String(definition.function_definition ?? "")
      .replace(/\/\*.*?\*\//gs, "").replace(/--[^\n]*/g, "")
      .toLowerCase().replace(/\s+/g, "");
    const plpgsqlBody = body.match(
      /as\$(?:[a-z0-9_]*)\$(beginif.+?endif;returnnew;end);?\$(?:[a-z0-9_]*)?\$;?$/,
    )?.[1] ?? "";
    const predicate = plpgsqlBody.match(/^beginif(.+?)thenraiseexception/);
    const canonicalPredicate =
      "new.tenant_id<>old.tenant_idornew.workspace_id<>old.workspace_idor" +
      "new.job_type<>old.job_typeornew.resource_idisdistinctfromold.resource_idor" +
      "new.due_at<>old.due_atornew.dedupe_key<>old.dedupe_key";
    if (!predicate || predicate[1] !== canonicalPredicate ||
        !/^beginif.+?thenraiseexception.+?;endif;returnnew;end$/.test(plpgsqlBody)) return false;
  }

  const workerExpected = new Set([
    "workos_control.claim_due_job(text,text[],integer)",
    "workos_control.finish_claimed_job(uuid,uuid,workos.job_state)",
    "workos_security.active_context_allows(uuid,uuid)",
    "workos_security.setting_uuid(text)",
    "workos_security.system_job_allows(uuid,uuid,uuid,text)",
  ]);
  return executeRows.every((row) => {
    const signature = normalizeSignature(row.signature);
    return (
      normalizeBoolean(row.worker_execute) === workerExpected.has(signature)
    );
  });
}

const CUSTOMER_ZERO_SEED_ALIASES = Object.freeze([
  "tenant", "workspace", "users", "memberships", "principal", "principal_user_link",
  "assignment", "assignment_principal", "action_scopes", "data_scopes",
  "foundation_work_object", "tasks", "commitment", "projection",
]);
export function validateCustomerZeroSeed(row) {
  return Boolean(row && sameStringSet(Object.keys(row), CUSTOMER_ZERO_SEED_ALIASES) &&
    CUSTOMER_ZERO_SEED_ALIASES.every((alias) => normalizeBoolean(row[alias])));
}

export function safeResultLine(passed, invariant) {
  const allowed = new Set([
    ...INVARIANT_NAMES,
    "connection",
    "query_error",
    "transaction_control",
  ]);
  const safeInvariant = allowed.has(invariant) ? invariant : "query_error";
  return `${passed ? "PASS" : "FAIL"} ${safeInvariant}`;
}

export const CATALOG_QUERIES = Object.freeze({
  transactionReadOnly:
    "select current_setting('transaction_read_only') = 'on' as is_read_only",
  migrationIdentity: `
    select
      session_user,
      current_user,
      role.rolcanlogin,
      role.rolsuper,
      role.rolcreaterole
    from pg_roles role
    where role.rolname = current_user
  `,
  roles: `
    select
      rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
      rolinherit, rolbypassrls, rolreplication
    from pg_roles
    where rolname = any($1::text[])
    order by rolname
  `,
  membershipColumns: `
    select column_name
    from information_schema.columns
    where table_schema = 'pg_catalog'
      and table_name = 'pg_auth_members'
    order by ordinal_position
  `,
  effectiveMemberships: `
    with recursive edges(member, granted_role, set_option) as (
      select member, roleid, set_option from pg_auth_members
    )
    select member::text, granted_role::text, set_option as can_assume
    from edges
  `,
  ledgerSchema: `
    select
      column_name,
      data_type,
      is_nullable,
      column_default
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'workos_migrations'
    order by ordinal_position
  `,
  ledgerOwner: `
    select owner.rolname as owner
    from pg_class relation
    join pg_namespace namespace on namespace.oid = relation.relnamespace
    join pg_roles owner on owner.oid = relation.relowner
    where namespace.nspname = 'public'
      and relation.relname = 'workos_migrations'
      and relation.relkind in ('r', 'p')
  `,
  ledgerRows: `
    select filename, checksum, applied_at
    from public.workos_migrations
    order by filename
  `,
  ledgerPrimaryKey: `
    select
      attribute.attname as column_name,
      migration_constraint.contype = 'p' as is_primary_key
    from pg_constraint as migration_constraint
    join pg_class as relation
      on relation.oid = migration_constraint.conrelid
    join pg_namespace as namespace
      on namespace.oid = relation.relnamespace
    join unnest(migration_constraint.conkey) with ordinality
      as key_column(attnum, ordinal_position)
      on true
    join pg_attribute as attribute
      on attribute.attrelid = relation.oid
     and attribute.attnum = key_column.attnum
    where namespace.nspname = 'public'
      and relation.relname = 'workos_migrations'
      and migration_constraint.contype = 'p'
    order by key_column.ordinal_position
  `,
  schemaOwnership: `
    select namespace.nspname as object_name, owner.rolname as owner
    from pg_namespace namespace
    join pg_roles owner on owner.oid = namespace.nspowner
    where namespace.nspname = any($1::text[])
    order by namespace.nspname
  `,
  schemaAcl: `
    with acl as (
      select namespace.nspname as schema_name, 'PUBLIC'::name as role_name,
        coalesce(bool_or(
          privilege.grantee = 0 and privilege.privilege_type = 'USAGE'
        ), false) as usage,
        coalesce(bool_or(
          privilege.grantee = 0 and privilege.privilege_type = 'CREATE'
        ), false) as create_privilege
      from pg_namespace namespace
      left join lateral aclexplode(
        coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))
      ) privilege on true
      where namespace.nspname in ('workos', 'workos_security', 'workos_control')
      group by namespace.oid, namespace.nspname
      union all
      select namespace.nspname as schema_name, roles.role_name,
        has_schema_privilege(roles.role_name, namespace.oid, 'USAGE') as usage,
        has_schema_privilege(roles.role_name, namespace.oid, 'CREATE') as create_privilege
      from pg_namespace namespace
      cross join (values ('workos_runtime'::name), ('workos_worker'::name),
        ('workos_security_definer'::name)) roles(role_name)
      where namespace.nspname in ('workos', 'workos_security', 'workos_control')
    )
    select schema_name, role_name, usage, create_privilege as create
    from acl
    order by schema_name, role_name
  `,
  tableOwnership: `
    select
      namespace.nspname || '.' || relation.relname as object_name,
      owner.rolname as owner
    from pg_class relation
    join pg_namespace namespace on namespace.oid = relation.relnamespace
    join pg_roles owner on owner.oid = relation.relowner
    where namespace.nspname in ('workos', 'workos_control')
      and relation.relkind in ('r', 'p')
    order by object_name
  `,
  unexpectedOwnership: `
    select count(*)::int as count
    from (
      select namespace.nspname, relation.relname, owner.rolname
      from pg_class relation
      join pg_namespace namespace on namespace.oid = relation.relnamespace
      join pg_roles owner on owner.oid = relation.relowner
      where namespace.nspname in ('workos', 'workos_security', 'workos_control')
        and relation.relkind in ('r', 'p')
        and owner.rolname in (
          'workos_runtime', 'workos_worker', 'workos_migrator',
          'workos_security_definer'
        )
      union all
      select namespace.nspname, null::name, owner.rolname
      from pg_namespace namespace
      join pg_roles owner on owner.oid = namespace.nspowner
      where namespace.nspname in ('workos', 'workos_security', 'workos_control')
        and owner.rolname in (
          'workos_runtime', 'workos_worker', 'workos_migrator',
          'workos_security_definer'
        )
    ) unexpected
  `,
  rls: `
    select
      namespace.nspname || '.' || relation.relname as object_name,
      relation.relrowsecurity,
      relation.relforcerowsecurity
    from pg_class relation
    join pg_namespace namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'workos'
      and relation.relkind in ('r', 'p')
    order by object_name
  `,
  policies: `
    select
      namespace.nspname || '.' || relation.relname || '.' || policy.polname
        as policy_key,
      policy.polcmd as command,
      policy.polpermissive as permissive,
      array(
        select case when role_oid = 0 then 'PUBLIC' else role.rolname end
        from unnest(policy.polroles) role_oid
        left join pg_roles role on role.oid = role_oid
        order by 1
      ) as roles,
      pg_get_expr(policy.polqual, policy.polrelid) as using_expression,
      pg_get_expr(policy.polwithcheck, policy.polrelid) as check_expression
    from pg_policy policy
    join pg_class relation on relation.oid = policy.polrelid
    join pg_namespace namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'workos'
    order by policy_key
  `,
  functions: `
    select
      namespace.nspname || '.' || procedure.proname || '(' ||
        oidvectortypes(procedure.proargtypes) || ')' as signature,
      owner.rolname as owner,
      procedure.prosecdef as security_definer,
      coalesce(procedure.proconfig, array[]::text[]) as config
    from pg_proc procedure
    join pg_namespace namespace on namespace.oid = procedure.pronamespace
    join pg_roles owner on owner.oid = procedure.proowner
    where namespace.nspname in ('workos_security', 'workos_control')
      and procedure.prokind = 'f'
    order by signature
  `,
  functionExecute: `
    select
      namespace.nspname || '.' || procedure.proname || '(' ||
        oidvectortypes(procedure.proargtypes) || ')' as signature,
      has_function_privilege('workos_runtime', procedure.oid, 'EXECUTE')
        as runtime_execute,
      has_function_privilege('workos_worker', procedure.oid, 'EXECUTE')
        as worker_execute,
      coalesce(
        (
          select bool_or(privilege.privilege_type = 'EXECUTE')
          from aclexplode(
            coalesce(
              procedure.proacl,
              acldefault('f', procedure.proowner)
            )
          ) privilege
          where privilege.grantee = 0
        ),
        false
      ) as public_execute
    from pg_proc procedure
    join pg_namespace namespace on namespace.oid = procedure.pronamespace
    where namespace.nspname in ('workos_security', 'workos_control')
      and procedure.prokind = 'f'
    order by signature
  `,
  publicSchema: `
    select
      coalesce(
        (
          select bool_or(privilege.privilege_type = 'USAGE')
          from pg_namespace public_namespace
          cross join lateral aclexplode(
            coalesce(
              public_namespace.nspacl,
              acldefault('n', public_namespace.nspowner)
            )
          ) privilege
          where public_namespace.nspname = 'public'
            and privilege.grantee = 0
        ),
        false
      ) as public_usage,
      coalesce(
        (
          select bool_or(privilege.privilege_type = 'CREATE')
          from pg_namespace public_namespace
          cross join lateral aclexplode(
            coalesce(
              public_namespace.nspacl,
              acldefault('n', public_namespace.nspowner)
            )
          ) privilege
          where public_namespace.nspname = 'public'
            and privilege.grantee = 0
        ),
        false
      ) as public_create,
      has_schema_privilege('workos_runtime', 'public', 'CREATE')
        as runtime_create,
      has_schema_privilege('workos_worker', 'public', 'CREATE')
        as worker_create,
      has_schema_privilege('workos_security_definer', 'public', 'CREATE')
        as security_definer_create,
      has_schema_privilege('workos_security_definer', 'public', 'USAGE')
        as security_definer_usage
  `,
  tableAcl: `
    with roles(role_name) as (
      values ('workos_runtime'::name), ('workos_worker'::name)
    )
    select
      roles.role_name::text,
      namespace.nspname || '.' || relation.relname as object_name,
      has_table_privilege(roles.role_name, relation.oid, 'SELECT') as select,
      has_table_privilege(roles.role_name, relation.oid, 'INSERT') as insert,
      has_table_privilege(roles.role_name, relation.oid, 'UPDATE') as update,
      has_table_privilege(roles.role_name, relation.oid, 'DELETE') as delete,
      has_table_privilege(roles.role_name, relation.oid, 'TRUNCATE') as truncate,
      has_table_privilege(roles.role_name, relation.oid, 'REFERENCES') as references,
      has_table_privilege(roles.role_name, relation.oid, 'TRIGGER') as trigger
    from roles
    cross join pg_class relation
    join pg_namespace namespace on namespace.oid = relation.relnamespace
    where namespace.nspname in ('workos', 'workos_control')
      and relation.relkind in ('r', 'p')
    order by roles.role_name, object_name
  `,
  jobEnvelopeAcl: `
    select roles.role_name::text, namespace.nspname || '.' || relation.relname as object_name,
      has_table_privilege(roles.role_name, relation.oid, 'SELECT') as select,
      has_table_privilege(roles.role_name, relation.oid, 'INSERT') as insert,
      has_table_privilege(roles.role_name, relation.oid, 'UPDATE') as update,
      has_table_privilege(roles.role_name, relation.oid, 'DELETE') as delete,
      has_table_privilege(roles.role_name, relation.oid, 'TRUNCATE') as truncate,
      has_table_privilege(roles.role_name, relation.oid, 'REFERENCES') as references,
      has_table_privilege(roles.role_name, relation.oid, 'TRIGGER') as trigger
    from (values ('workos_runtime'::name), ('workos_worker'::name),
      ('workos_security_definer'::name)) roles(role_name)
    cross join pg_class relation join pg_namespace namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = 'workos_control' and relation.relname = 'job_envelopes'
  `,
  jobEnvelopeFunctionDefinition: `
    select namespace.nspname || '.' || procedure.proname || '(' ||
      oidvectortypes(procedure.proargtypes) || ')' as signature,
      pg_get_functiondef(procedure.oid) as function_definition
    from pg_proc procedure join pg_namespace namespace on namespace.oid = procedure.pronamespace
    where namespace.nspname = 'workos_security'
      and procedure.proname = 'prevent_job_envelope_scope_change'
  `,
  jobEnvelopeTrigger: `
    select
      trigger.tgname as trigger_name,
      function_namespace.nspname || '.' || procedure.proname || '(' ||
        oidvectortypes(procedure.proargtypes) || ')'
        as function_signature,
      (trigger.tgtype & 1) = 1 as is_row,
      (trigger.tgtype & 2) = 2 as is_before,
      (trigger.tgtype & 16) = 16 as is_update,
      trigger.tgenabled as enabled
    from pg_trigger trigger
    join pg_class relation on relation.oid = trigger.tgrelid
    join pg_namespace namespace on namespace.oid = relation.relnamespace
    join pg_proc procedure on procedure.oid = trigger.tgfoid
    join pg_namespace function_namespace
      on function_namespace.oid = procedure.pronamespace
    where namespace.nspname = 'workos_control'
      and relation.relname = 'job_envelopes'
      and not trigger.tgisinternal
    order by trigger.tgname
  `,
  customerZeroSeed: `
    select
      (
        select count(*) = 1 from workos.tenants
        where id = '10000000-0000-4000-8000-000000000001'
          and name = 'W. Coleman & Co'
          and status = 'ACTIVE'
      ) as tenant,
      (
        select count(*) = 1 from workos.workspaces
        where id = '20000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and name = 'Advisory Operations'
          and workspace_type = 'SMALL_PROFESSIONAL'
          and security_domain = 'wcc-customer-zero-advisory'
          and status = 'ACTIVE'
      ) as workspace,
      (
        select count(*) = 2 from workos.users
        where id in (
          '30000000-0000-4000-8000-000000000001',
          '30000000-0000-4000-8000-000000000002'
        )
          and status = 'ACTIVE'
          and ((id = '30000000-0000-4000-8000-000000000001' and display_name = 'Customer Zero Operator')
            or (id = '30000000-0000-4000-8000-000000000002' and display_name = 'Customer Zero Director'))
      ) as users,
      (
        select count(*) = 2 from workos.workspace_memberships
        where id in (
          '40000000-0000-4000-8000-000000000001',
          '40000000-0000-4000-8000-000000000002'
        )
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and status = 'ACTIVE'
          and ((id = '40000000-0000-4000-8000-000000000001'
            and user_id = '30000000-0000-4000-8000-000000000001' and role = 'OPERATOR')
            or (id = '40000000-0000-4000-8000-000000000002'
            and user_id = '30000000-0000-4000-8000-000000000002' and role = 'PRINCIPAL'))
      ) as memberships,
      (
        select count(*) = 1 from workos.principals
        where id = '50000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and status = 'ACTIVE'
          and principal_type = 'PERSON'
          and display_name = 'Customer Zero Director'
      ) as principal,
      (
        select count(*) = 1 from workos.operator_assignments
        where id = '60000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and operator_user_id = '30000000-0000-4000-8000-000000000001'
          and service_profile = 'CUSTOMER_ZERO_EA'
          and status = 'ACTIVE'
          and context_version = 1
      ) as assignment,
      (
        select count(*) = 1 from workos.principal_user_links
        where id = '51000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and principal_id = '50000000-0000-4000-8000-000000000001'
          and user_id = '30000000-0000-4000-8000-000000000002'
      ) as principal_user_link,
      (
        select count(*) = 1 from workos.operator_assignment_principals
        where assignment_id = '60000000-0000-4000-8000-000000000001'
          and principal_id = '50000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
      ) as assignment_principal,
      (
        select count(*) = 2 from workos.operator_assignment_action_scopes
        where assignment_id = '60000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and ((id = '61000000-0000-4000-8000-000000000001' and action_class = 'INTERNAL_TASK_STATE' and authority_mode = 'PREPARE')
            or (id = '61000000-0000-4000-8000-000000000002' and action_class = 'EXTERNAL_COMMUNICATION' and authority_mode = 'BLOCKED'))
      ) as action_scopes,
      (
        select count(*) = 1 from workos.operator_assignment_data_scopes
        where assignment_id = '60000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and id = '62000000-0000-4000-8000-000000000001'
          and scope_type = 'WORKSPACE' and scope_key = 'FOUNDATION_SEED_ONLY'
      ) as data_scopes,
      (
        select count(*) = 1 from workos.work_objects
        where id = '70000000-0000-4000-8000-000000000001'
          and accountable_principal_id = '50000000-0000-4000-8000-000000000001'
          and owner_user_id = '30000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and work_type = 'FOUNDATION_READINESS'
          and title = 'Customer Zero foundation readiness'
      ) as foundation_work_object,
      (
        select count(*) = 2 from workos.tasks
        where id in (
          '71000000-0000-4000-8000-000000000001',
          '71000000-0000-4000-8000-000000000002'
        )
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and ((id = '71000000-0000-4000-8000-000000000001'
            and work_object_id = '70000000-0000-4000-8000-000000000001'
            and intent = 'Verify tenant and workspace isolation' and status = 'IN_PROGRESS'
            and accountable_owner_user_id = '30000000-0000-4000-8000-000000000001'
            and next_action_owner_user_id = '30000000-0000-4000-8000-000000000001'
            and priority = 'HIGH'
            and completion_condition = '{"type":"test_gate","suite":"stage_a_rls"}'::jsonb
            and waiting_on_type is null and waiting_on_key is null)
            or (id = '71000000-0000-4000-8000-000000000002'
            and work_object_id = '70000000-0000-4000-8000-000000000001'
            and intent = 'Review Stage A completion report' and status = 'WAITING'
            and accountable_owner_user_id = '30000000-0000-4000-8000-000000000001'
            and next_action_owner_user_id = '30000000-0000-4000-8000-000000000002'
            and priority = 'NORMAL'
            and completion_condition = '{"type":"human_confirmation","required_role":"PRINCIPAL"}'::jsonb
            and waiting_on_type = 'STAGE_GATE' and waiting_on_key = 'STAGE_A_APPROVAL'))
      ) as tasks,
      (
        select count(*) = 1 from workos.commitments
        where id = '72000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and work_object_id = '70000000-0000-4000-8000-000000000001'
          and promisor_principal_id = '50000000-0000-4000-8000-000000000001'
          and beneficiary_principal_id = '50000000-0000-4000-8000-000000000001'
          and commitment_text = 'Do not proceed to Stage B without explicit approval'
          and status = 'OPEN'
          and completion_condition = '{"type":"stage_boundary","required_approval":"STAGE_B"}'::jsonb
      ) as commitment,
      (
        select count(*) = 1 from workos.portfolio_metadata_projection
        where id = '73000000-0000-4000-8000-000000000001'
          and tenant_id = '10000000-0000-4000-8000-000000000001'
          and workspace_id = '20000000-0000-4000-8000-000000000001'
          and assignment_id = '60000000-0000-4000-8000-000000000001'
          and category = 'Foundation readiness'
          and urgency = 'HIGH'
          and age_seconds = 0
          and status = 'IN_PROGRESS'
      ) as projection
  `,
});

function effectiveMembershipQuery(supportedColumns) {
  if (!supportedColumns.includes("set_option")) {
    return `select null::text as member, null::text as granted_role,
      false as can_assume where false`;
  }
  return `
    with recursive set_edges(member, granted_role) as (
      select member, roleid
      from pg_auth_members
      where set_option
      union
      select edge.member, membership.roleid
      from set_edges edge
      join pg_auth_members membership
        on membership.member = edge.granted_role
       and membership.set_option
    )
    select member_role.rolname as member,
      granted_role.rolname as granted_role,
      true as can_assume
    from set_edges edge
    join pg_roles member_role on member_role.oid = edge.member
    join pg_roles granted_role on granted_role.oid = edge.granted_role
    where member_role.rolname = current_user
       or member_role.rolname in ('workos_runtime', 'workos_worker',
         'workos_migrator', 'workos_schema_owner', 'workos_security_definer')
  `;
}

export { effectiveMembershipQuery };

export function assertReadOnlyQueryManifest(queries = CATALOG_QUERIES) {
  const forbidden =
    /\b(?:insert\s+into|update\s+(?:only\s+)?[a-z_"][a-z0-9_.$"]*\s+set|delete\s+from|merge\s+into|copy\s+.+\s+from|create\s+(?:or\s+replace\s+)?(?:table|schema|role|function|trigger|extension)|alter\s+(?:table|schema|role|function|default)|drop\s+(?:table|schema|role|function|trigger|extension)|truncate\s+(?:table\s+)?|grant\s+|revoke\s+|set\s+role|call\s+|do\s+\$)/iu;
  return Object.values(queries).every((sql) => {
    if (typeof sql !== "string") return false;
    const normalized = sql.trim();
    return /^(?:select|with|show)\b/iu.test(normalized) && !forbidden.test(normalized);
  });
}

export async function safeQuery(client, sql, parameters = []) {
  if (!assertReadOnlyQueryManifest({ query: sql })) {
    throw new AuditInvariantError("query_error");
  }
  try {
    return await client.query(sql, parameters);
  } catch {
    throw new AuditQueryError();
  }
}

function result(name, passed) {
  return { name, passed: Boolean(passed) };
}

export async function runStageAAudit(client, migrationManifest) {
  if (!assertReadOnlyQueryManifest()) {
    throw new AuditInvariantError("migration_manifest");
  }

  const results = [];
  const transactionResult = await safeQuery(
    client,
    CATALOG_QUERIES.transactionReadOnly,
  );
  results.push(
    result(
      "transaction_read_only",
      normalizeBoolean(transactionResult.rows[0]?.is_read_only),
    ),
  );

  const identityResult = await safeQuery(client, CATALOG_QUERIES.migrationIdentity);
  const identity = identityResult.rows[0];

  const roles = await safeQuery(client, CATALOG_QUERIES.roles, [
    Object.keys(CANONICAL_ROLES),
  ]);
  results.push(result("role_attributes", validateRoleAttributes(roles.rows)));

  const membershipColumnsResult = await safeQuery(
    client,
    CATALOG_QUERIES.membershipColumns,
  );
  const supportedColumns = membershipColumnsResult.rows.map(
    (row) => row.column_name,
  );
  const optionalColumns = ["inherit_option", "set_option"].filter((column) =>
    supportedColumns.includes(column),
  );
  const membershipQuery = `
    select
      member.rolname as member,
      granted.rolname as granted_role,
      grantor.rolname as grantor,
      membership.admin_option
      ${
        optionalColumns.length > 0
          ? `, ${optionalColumns.map((column) => `membership.${column}`).join(", ")}`
          : ""
      }
    from pg_auth_members membership
    join pg_roles member on member.oid = membership.member
    join pg_roles granted on granted.oid = membership.roleid
    join pg_roles grantor on grantor.oid = membership.grantor
    where member.rolname = any($1::text[])
       or granted.rolname = any($1::text[])
       or member.rolname = current_user
    order by member.rolname, granted.rolname
  `;
  if (!assertReadOnlyQueryManifest({ membershipQuery })) {
    throw new AuditInvariantError("role_memberships");
  }
  const memberships = await safeQuery(client, membershipQuery, [
    Object.keys(CANONICAL_ROLES),
  ]);
  const effectiveQuery = effectiveMembershipQuery(supportedColumns);
  if (!assertReadOnlyQueryManifest({ effectiveMembershipQuery: effectiveQuery })) {
    throw new AuditInvariantError("role_memberships");
  }
  const effectiveMemberships = await safeQuery(client, effectiveQuery);
  const identityEffective = new Set(
    effectiveMemberships.rows
      .filter((row) => row.member === identity?.current_user && normalizeBoolean(row.can_assume))
      .map((row) => row.granted_role),
  );
  const identityWithMemberships = {
    ...identity,
    can_assume_schema_owner: identityEffective.has("workos_schema_owner"),
    can_assume_security_definer: identityEffective.has("workos_security_definer"),
  };
  results.push(result("migration_identity", validateMigrationIdentity(identityWithMemberships)));
  results.push(
    result(
      "role_memberships",
      validateMemberships({
        rows: memberships.rows,
        supportedColumns,
        effectiveRows: effectiveMemberships.rows,
        migrationIdentity: {
          can_assume_schema_owner: identityWithMemberships.can_assume_schema_owner,
          can_assume_security_definer: identityWithMemberships.can_assume_security_definer,
          current_user: identity?.current_user,
        },
      }),
    ),
  );

  const ledgerSchema = await safeQuery(client, CATALOG_QUERIES.ledgerSchema);
  const ledgerPrimaryKey = await safeQuery(client, CATALOG_QUERIES.ledgerPrimaryKey);
  const ledgerOwner = await safeQuery(client, CATALOG_QUERIES.ledgerOwner);
  results.push(
    result(
      "migration_ledger_schema",
       validateLedgerSchema(ledgerSchema.rows) &&
         validateLedgerPrimaryKey(ledgerPrimaryKey.rows) &&
        ledgerOwner.rows.length === 1 &&
        ledgerOwner.rows[0].owner === identity?.current_user,
    ),
  );
  const ledgerRows = await safeQuery(client, CATALOG_QUERIES.ledgerRows);
  results.push(
    result(
      "migration_ledger_rows",
      validateMigrationLedger(ledgerRows.rows, migrationManifest),
    ),
  );

  const schemaOwnership = await safeQuery(
    client,
    CATALOG_QUERIES.schemaOwnership,
    [["workos", "workos_security", "workos_control"]],
  );
  const schemaAcl = await safeQuery(client, CATALOG_QUERIES.schemaAcl);
  results.push(result("schema_ownership", validateSchemaAcl(schemaAcl.rows) &&
    validateOwnership(schemaOwnership.rows, ["workos", "workos_security", "workos_control"], "workos_schema_owner")));
  const tableOwnership = await safeQuery(client, CATALOG_QUERIES.tableOwnership);
  const unexpectedOwnership = await safeQuery(
    client,
    CATALOG_QUERIES.unexpectedOwnership,
  );
  results.push(
    result(
      "table_ownership",
      validateOwnership(
        tableOwnership.rows,
        OWNED_TABLES,
        "workos_schema_owner",
      ) && unexpectedOwnership.rows[0]?.count === 0,
    ),
  );

  const rls = await safeQuery(client, CATALOG_QUERIES.rls);
  results.push(result("rls_enforcement", validateRls(rls.rows)));
  const policies = await safeQuery(client, CATALOG_QUERIES.policies);
  results.push(result("policy_manifest", validatePolicies(policies.rows)));

  const functions = await safeQuery(client, CATALOG_QUERIES.functions);
  results.push(
    result(
      "security_definer_manifest",
      validateSecurityDefinerFunctions(functions.rows),
    ),
  );
  results.push(
    result(
      "setting_uuid_security_invoker",
      validateSettingUuidInvoker(functions.rows),
    ),
  );

  const functionExecute = await safeQuery(
    client,
    CATALOG_QUERIES.functionExecute,
  );
  const executeAllowlists = deriveFunctionExecuteAllowlists(migrationManifest);
  results.push(
    result(
      "function_execute_allowlist",
      validateFunctionExecute(functionExecute.rows, executeAllowlists),
    ),
  );
  results.push(
    result(
      "public_function_execute",
      validateNoPublicFunctionExecute(functionExecute.rows),
    ),
  );

  const publicSchema = await safeQuery(client, CATALOG_QUERIES.publicSchema);
  results.push(
    result(
      "public_schema_hardening",
      validatePublicSchemaHardening(publicSchema.rows[0]),
    ),
  );

  const tableAcl = await safeQuery(client, CATALOG_QUERIES.tableAcl);
  results.push(result("table_acl_manifest", validateTableAcl(tableAcl.rows)));
  results.push(
    result(
      "append_only_boundaries",
      validateAppendOnlyBoundaries(tableAcl.rows),
    ),
  );

  const trigger = await safeQuery(client, CATALOG_QUERIES.jobEnvelopeTrigger);
  const jobAcl = await safeQuery(client, CATALOG_QUERIES.jobEnvelopeAcl);
  const jobDefinition = await safeQuery(client, CATALOG_QUERIES.jobEnvelopeFunctionDefinition);
  results.push(
    result(
      "job_envelope_control_plane",
      validateJobEnvelopeControlPlane({
        triggerRows: trigger.rows,
        aclRows: jobAcl.rows,
        executeRows: functionExecute.rows,
        functionDefinitionRows: jobDefinition.rows,
      }),
    ),
  );

  const customerZeroSeed = await safeQuery(
    client,
    CATALOG_QUERIES.customerZeroSeed,
  );
  results.push(
    result(
      "customer_zero_seed",
      validateCustomerZeroSeed(customerZeroSeed.rows[0]),
    ),
  );

  return results;
}

export async function executeAuditCli({
  environment,
  migrationsDirectory,
  createClient,
  writeLine,
}) {
  let client;
  let transactionStarted = false;
  let failed = false;

  try {
    const migrationUrl = requireMigrationEnvironment(environment);
    writeLine(safeResultLine(true, "environment_isolation"));

    const manifest = await loadMigrationManifest(migrationsDirectory);
    writeLine(safeResultLine(true, "migration_manifest"));

    try {
      client = createClient(migrationUrl);
      await client.connect();
    } catch {
      writeLine(safeResultLine(false, "connection"));
      return 1;
    }

    try {
      await client.query(
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
      );
      transactionStarted = true;
    } catch {
      writeLine(safeResultLine(false, "transaction_control"));
      return 1;
    }

    let results;
    try {
      results = await runStageAAudit(client, manifest);
    } catch (error) {
      writeLine(
        safeResultLine(
          false,
          error instanceof AuditQueryError ? "query_error" : error.invariant,
        ),
      );
      return 1;
    }

    for (const auditResult of results) {
      writeLine(safeResultLine(auditResult.passed, auditResult.name));
      failed ||= !auditResult.passed;
    }
  } catch (error) {
    writeLine(
      safeResultLine(
        false,
        error instanceof AuditInvariantError
          ? error.invariant
          : "migration_manifest",
      ),
    );
    return 1;
  } finally {
    if (client) {
      if (transactionStarted) {
        try {
          await client.query("ROLLBACK");
        } catch {
          failed = true;
          writeLine(safeResultLine(false, "transaction_control"));
        }
      }
      try {
        await client.end();
      } catch {
        failed = true;
        writeLine(safeResultLine(false, "connection"));
      }
    }
  }

  return failed ? 1 : 0;
}