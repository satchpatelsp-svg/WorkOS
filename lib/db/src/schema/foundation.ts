import {
  bigint,
  boolean,
  integer,
  jsonb,
  pgEnum,
  pgSchema,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

export const workosSchema = pgSchema("workos");

export const recordStatus = pgEnum("record_status", [
  "ACTIVE",
  "INACTIVE",
  "SUSPENDED",
  "REVOKED",
]);
export const principalType = pgEnum("principal_type", [
  "PERSON",
  "ORGANISATION",
  "LEGAL_ENTITY",
]);
export const membershipRole = pgEnum("membership_role", [
  "MEMBER",
  "OPERATOR",
  "PRINCIPAL",
  "WORKSPACE_ADMIN",
]);
export const workState = pgEnum("work_state", [
  "PROPOSED",
  "OPEN",
  "IN_PROGRESS",
  "WAITING",
  "AWAITING_APPROVAL",
  "BLOCKED",
  "HELD",
  "EXECUTING",
  "VERIFYING",
  "COMPLETED",
  "FAILED",
  "SUPERSEDED",
  "CANCELLED",
]);
export const workObjectState = pgEnum("work_object_state", [
  "ACTIVE",
  "PAUSED",
  "COMPLETED",
  "ARCHIVED",
]);
export const actorType = pgEnum("actor_type", [
  "USER",
  "OPERATOR_ASSIGNMENT",
  "SYSTEM_JOB",
  "SERVICE",
]);
export const executorType = pgEnum("executor_type", [
  "USER",
  "OPERATOR_ASSIGNMENT",
  "SERVICE",
]);
export const attentionPriority = pgEnum("attention_priority", [
  "LOW",
  "NORMAL",
  "HIGH",
  "CRITICAL",
]);
export const jobState = pgEnum("job_state", [
  "PENDING",
  "CLAIMED",
  "COMPLETED",
  "FAILED",
  "CANCELLED",
]);
export const effectState = pgEnum("effect_state", [
  "PENDING",
  "RESERVED",
  "IN_PROGRESS",
  "SUCCEEDED",
  "FAILED",
  "UNKNOWN",
  "REQUIRES_RECONCILIATION",
]);

const createdAt = () =>
  timestamp("created_at", { withTimezone: true }).notNull().defaultNow();
const updatedAt = () =>
  timestamp("updated_at", { withTimezone: true }).notNull().defaultNow();

export const tenantsTable = workosSchema.table("tenants", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  status: recordStatus("status").notNull().default("ACTIVE"),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const workspacesTable = workosSchema.table(
  "workspaces",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    name: text("name").notNull(),
    workspaceType: text("workspace_type").notNull(),
    securityDomain: text("security_domain").notNull(),
    status: recordStatus("status").notNull().default("ACTIVE"),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    uniqueIndex("workspaces_tenant_name").on(table.tenantId, table.name),
    uniqueIndex("workspaces_security_domain").on(
      table.tenantId,
      table.securityDomain,
    ),
  ],
);

export const usersTable = workosSchema.table("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  displayName: text("display_name").notNull(),
  locale: text("locale").notNull().default("en-GB"),
  timezone: text("timezone").notNull().default("Europe/London"),
  status: recordStatus("status").notNull().default("ACTIVE"),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const externalIdentitiesTable = workosSchema.table(
  "external_identities",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id").notNull(),
    provider: text("provider").notNull(),
    providerTenantId: text("provider_tenant_id").notNull(),
    providerSubjectId: text("provider_subject_id").notNull(),
    email: text("email"),
    metadata: jsonb("metadata").notNull().default({}),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    disabledAt: timestamp("disabled_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex("external_identity_provider_subject").on(
      table.provider,
      table.providerTenantId,
      table.providerSubjectId,
    ),
  ],
);

export const workspaceMembershipsTable = workosSchema.table(
  "workspace_memberships",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    userId: uuid("user_id").notNull(),
    role: membershipRole("role").notNull(),
    status: recordStatus("status").notNull().default("ACTIVE"),
    effectiveFrom: timestamp("effective_from", { withTimezone: true })
      .notNull()
      .defaultNow(),
    effectiveTo: timestamp("effective_to", { withTimezone: true }),
    contextVersion: bigint("context_version", { mode: "number" })
      .notNull()
      .default(1),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    uniqueIndex("workspace_membership_user").on(
      table.tenantId,
      table.workspaceId,
      table.userId,
    ),
  ],
);

export const principalsTable = workosSchema.table("principals", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  workspaceId: uuid("workspace_id").notNull(),
  principalType: principalType("principal_type").notNull(),
  displayName: text("display_name").notNull(),
  status: recordStatus("status").notNull().default("ACTIVE"),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const principalUserLinksTable = workosSchema.table(
  "principal_user_links",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    principalId: uuid("principal_id").notNull(),
    userId: uuid("user_id").notNull(),
    relationshipType: text("relationship_type")
      .notNull()
      .default("REPRESENTS_SELF"),
    effectiveFrom: timestamp("effective_from", { withTimezone: true })
      .notNull()
      .defaultNow(),
    effectiveTo: timestamp("effective_to", { withTimezone: true }),
    createdAt: createdAt(),
  },
);

export const operatorAssignmentsTable = workosSchema.table(
  "operator_assignments",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    operatorUserId: uuid("operator_user_id").notNull(),
    serviceProfile: text("service_profile").notNull(),
    status: recordStatus("status").notNull().default("ACTIVE"),
    effectiveFrom: timestamp("effective_from", { withTimezone: true })
      .notNull()
      .defaultNow(),
    effectiveTo: timestamp("effective_to", { withTimezone: true }),
    contextVersion: bigint("context_version", { mode: "number" })
      .notNull()
      .default(1),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
);

export const operatorAssignmentPrincipalsTable = workosSchema.table(
  "operator_assignment_principals",
  {
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    assignmentId: uuid("assignment_id").notNull(),
    principalId: uuid("principal_id").notNull(),
    createdAt: createdAt(),
  },
  (table) => [
    primaryKey({
      columns: [
        table.tenantId,
        table.workspaceId,
        table.assignmentId,
        table.principalId,
      ],
    }),
  ],
);

export const operatorAssignmentActionScopesTable = workosSchema.table(
  "operator_assignment_action_scopes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    assignmentId: uuid("assignment_id").notNull(),
    actionClass: text("action_class").notNull(),
    authorityMode: text("authority_mode").notNull(),
    effectiveFrom: timestamp("effective_from", { withTimezone: true })
      .notNull()
      .defaultNow(),
    effectiveTo: timestamp("effective_to", { withTimezone: true }),
    createdAt: createdAt(),
  },
);

export const operatorAssignmentDataScopesTable = workosSchema.table(
  "operator_assignment_data_scopes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    assignmentId: uuid("assignment_id").notNull(),
    scopeType: text("scope_type").notNull(),
    scopeKey: text("scope_key").notNull(),
    effectiveFrom: timestamp("effective_from", { withTimezone: true })
      .notNull()
      .defaultNow(),
    effectiveTo: timestamp("effective_to", { withTimezone: true }),
    createdAt: createdAt(),
  },
);

export const portfolioContextsTable = workosSchema.table("portfolio_contexts", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").notNull(),
  purpose: text("purpose").notNull(),
  snapshotHash: text("snapshot_hash").notNull(),
  createdAt: createdAt(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});

export const portfolioContextAssignmentsTable = workosSchema.table(
  "portfolio_context_assignments",
  {
    portfolioContextId: uuid("portfolio_context_id").notNull(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    assignmentId: uuid("assignment_id").notNull(),
  },
  (table) => [
    primaryKey({
      columns: [
        table.portfolioContextId,
        table.tenantId,
        table.workspaceId,
        table.assignmentId,
      ],
    }),
  ],
);

export const portfolioMetadataProjectionTable = workosSchema.table(
  "portfolio_metadata_projection",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    assignmentId: uuid("assignment_id").notNull(),
    category: text("category").notNull(),
    urgency: attentionPriority("urgency").notNull().default("NORMAL"),
    ageSeconds: bigint("age_seconds", { mode: "number" }).notNull().default(0),
    slaDueAt: timestamp("sla_due_at", { withTimezone: true }),
    status: text("status").notNull(),
    refreshedAt: timestamp("refreshed_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
);

export const workObjectsTable = workosSchema.table("work_objects", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  workspaceId: uuid("workspace_id").notNull(),
  workType: text("work_type").notNull(),
  title: text("title").notNull(),
  status: workObjectState("status").notNull().default("ACTIVE"),
  accountablePrincipalId: uuid("accountable_principal_id"),
  ownerUserId: uuid("owner_user_id"),
  version: bigint("version", { mode: "number" }).notNull().default(1),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const tasksTable = workosSchema.table("tasks", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  workspaceId: uuid("workspace_id").notNull(),
  workObjectId: uuid("work_object_id"),
  intent: text("intent").notNull(),
  status: workState("status").notNull().default("OPEN"),
  accountableOwnerUserId: uuid("accountable_owner_user_id"),
  nextActionOwnerUserId: uuid("next_action_owner_user_id"),
  waitingOnType: text("waiting_on_type"),
  waitingOnKey: text("waiting_on_key"),
  nextCheckAt: timestamp("next_check_at", { withTimezone: true }),
  dueAt: timestamp("due_at", { withTimezone: true }),
  priority: attentionPriority("priority").notNull().default("NORMAL"),
  completionCondition: jsonb("completion_condition").notNull(),
  resolutionEventId: uuid("resolution_event_id"),
  supersededByTaskId: uuid("superseded_by_task_id"),
  blockedReason: text("blocked_reason"),
  heldReason: text("held_reason"),
  version: bigint("version", { mode: "number" }).notNull().default(1),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const taskExecutorAssignmentsTable = workosSchema.table(
  "task_executor_assignments",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    taskId: uuid("task_id").notNull(),
    executorType: executorType("executor_type").notNull(),
    executorUserId: uuid("executor_user_id"),
    executorAssignmentId: uuid("executor_assignment_id"),
    executorServiceId: text("executor_service_id"),
    effectiveFrom: timestamp("effective_from", { withTimezone: true })
      .notNull()
      .defaultNow(),
    effectiveTo: timestamp("effective_to", { withTimezone: true }),
    isCurrent: boolean("is_current").notNull().default(true),
    createdAt: createdAt(),
  },
);

export const commitmentsTable = workosSchema.table("commitments", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  workspaceId: uuid("workspace_id").notNull(),
  workObjectId: uuid("work_object_id"),
  promisorPrincipalId: uuid("promisor_principal_id").notNull(),
  beneficiaryPrincipalId: uuid("beneficiary_principal_id").notNull(),
  commitmentText: text("commitment_text").notNull(),
  dueAt: timestamp("due_at", { withTimezone: true }),
  status: workState("status").notNull().default("OPEN"),
  completionCondition: jsonb("completion_condition").notNull(),
  version: bigint("version", { mode: "number" }).notNull().default(1),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const activityEventsTable = workosSchema.table("activity_events", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  workspaceId: uuid("workspace_id").notNull(),
  eventType: text("event_type").notNull(),
  occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull(),
  actorType: actorType("actor_type").notNull(),
  actorUserId: uuid("actor_user_id"),
  actorAssignmentId: uuid("actor_assignment_id"),
  actorSystemJobId: uuid("actor_system_job_id"),
  actorServiceId: text("actor_service_id"),
  representedPrincipalId: uuid("represented_principal_id"),
  subjectSnapshot: jsonb("subject_snapshot").notNull().default([]),
  sourceSnapshot: jsonb("source_snapshot"),
  payload: jsonb("payload").notNull(),
  causationId: uuid("causation_id"),
  correlationId: uuid("correlation_id"),
  correctionOfEventId: uuid("correction_of_event_id"),
  createdAt: createdAt(),
});

export const auditRecordsTable = workosSchema.table("audit_records", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  workspaceId: uuid("workspace_id").notNull(),
  actorType: actorType("actor_type").notNull(),
  actorSnapshot: jsonb("actor_snapshot").notNull(),
  representedPrincipalId: uuid("represented_principal_id"),
  operation: text("operation").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: uuid("resource_id"),
  beforeVersion: bigint("before_version", { mode: "number" }),
  afterVersion: bigint("after_version", { mode: "number" }),
  requestId: text("request_id").notNull(),
  correlationId: uuid("correlation_id"),
  result: text("result").notNull(),
  reasonCode: text("reason_code"),
  safeMetadata: jsonb("safe_metadata").notNull().default({}),
  correctionOfRecordId: uuid("correction_of_record_id"),
  occurredAt: timestamp("occurred_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const workStateTransitionsTable = workosSchema.table(
  "work_state_transitions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    entityType: text("entity_type").notNull(),
    entityId: uuid("entity_id").notNull(),
    fromState: text("from_state"),
    toState: text("to_state").notNull(),
    actorSnapshot: jsonb("actor_snapshot").notNull(),
    reason: text("reason"),
    eventId: uuid("event_id"),
    correctionOfTransitionId: uuid("correction_of_transition_id"),
    occurredAt: timestamp("occurred_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
);

export const outboxMessagesTable = workosSchema.table("outbox_messages", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  workspaceId: uuid("workspace_id").notNull(),
  eventId: uuid("event_id"),
  jobType: text("job_type").notNull(),
  resourceId: uuid("resource_id"),
  payload: jsonb("payload").notNull(),
  availableAt: timestamp("available_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  createdAt: createdAt(),
});

export const effectInstancesTable = workosSchema.table(
  "effect_instances",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    taskId: uuid("task_id"),
    commitmentId: uuid("commitment_id"),
    transitionCode: text("transition_code").notNull(),
    occurrenceId: text("occurrence_id").notNull(),
    effectFingerprint: text("effect_fingerprint").notNull(),
    createdAt: createdAt(),
  },
  (table) => [
    uniqueIndex("effect_instance_fingerprint").on(
      table.tenantId,
      table.workspaceId,
      table.effectFingerprint,
    ),
  ],
);

export const executionGuardsTable = workosSchema.table(
  "execution_guards",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull(),
    workspaceId: uuid("workspace_id").notNull(),
    effectInstanceId: uuid("effect_instance_id").notNull(),
    idempotencyKey: text("idempotency_key").notNull(),
    status: effectState("status").notNull().default("PENDING"),
    providerIdempotencyKey: text("provider_idempotency_key"),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (table) => [
    uniqueIndex("execution_guard_effect").on(
      table.tenantId,
      table.workspaceId,
      table.effectInstanceId,
    ),
    uniqueIndex("execution_guard_idempotency").on(
      table.tenantId,
      table.workspaceId,
      table.idempotencyKey,
    ),
  ],
);

export const jobClaimEventsTable = workosSchema.table("job_claim_events", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull(),
  workspaceId: uuid("workspace_id").notNull(),
  jobId: uuid("job_id").notNull(),
  jobType: text("job_type").notNull(),
  resourceId: uuid("resource_id"),
  transition: text("transition").notNull(),
  workerId: text("worker_id"),
  claimTokenHash: text("claim_token_hash"),
  occurredAt: timestamp("occurred_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export type Tenant = typeof tenantsTable.$inferSelect;
export type Workspace = typeof workspacesTable.$inferSelect;
export type User = typeof usersTable.$inferSelect;
export type WorkspaceMembership = typeof workspaceMembershipsTable.$inferSelect;
export type Principal = typeof principalsTable.$inferSelect;
export type OperatorAssignment = typeof operatorAssignmentsTable.$inferSelect;
export type WorkObject = typeof workObjectsTable.$inferSelect;
export type Task = typeof tasksTable.$inferSelect;
export type Commitment = typeof commitmentsTable.$inferSelect;