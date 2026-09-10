import { z } from "zod";

export const taskStates = [
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
] as const;

export const taskStateSchema = z.enum(taskStates);
export type TaskState = z.infer<typeof taskStateSchema>;

export const completionConditionSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("test_gate"),
    suite: z.string().min(1),
  }),
  z.object({
    type: z.literal("human_confirmation"),
    required_role: z.string().min(1),
  }),
  z.object({
    type: z.literal("source_state"),
    source: z.string().min(1),
    condition: z.string().min(1),
    source_ref: z.string().min(1),
  }),
  z.object({
    type: z.literal("stage_boundary"),
    required_approval: z.string().min(1),
  }),
]);
export type CompletionCondition = z.infer<typeof completionConditionSchema>;

const allowedTransitions: Readonly<Record<TaskState, readonly TaskState[]>> = {
  PROPOSED: ["OPEN", "CANCELLED", "SUPERSEDED"],
  OPEN: ["IN_PROGRESS", "WAITING", "AWAITING_APPROVAL", "BLOCKED", "HELD", "CANCELLED", "SUPERSEDED"],
  IN_PROGRESS: ["WAITING", "AWAITING_APPROVAL", "BLOCKED", "HELD", "EXECUTING", "VERIFYING", "COMPLETED", "FAILED", "CANCELLED", "SUPERSEDED"],
  WAITING: ["OPEN", "IN_PROGRESS", "BLOCKED", "HELD", "COMPLETED", "CANCELLED", "SUPERSEDED"],
  AWAITING_APPROVAL: ["OPEN", "EXECUTING", "HELD", "CANCELLED", "SUPERSEDED"],
  BLOCKED: ["OPEN", "IN_PROGRESS", "HELD", "CANCELLED", "SUPERSEDED"],
  HELD: ["OPEN", "IN_PROGRESS", "CANCELLED", "SUPERSEDED"],
  EXECUTING: ["VERIFYING", "COMPLETED", "FAILED", "HELD"],
  VERIFYING: ["COMPLETED", "FAILED", "HELD"],
  COMPLETED: [],
  FAILED: ["OPEN", "IN_PROGRESS", "HELD", "CANCELLED", "SUPERSEDED"],
  SUPERSEDED: [],
  CANCELLED: [],
};

export function canTransitionTask(from: TaskState, to: TaskState): boolean {
  return allowedTransitions[from].includes(to);
}

export function assertTaskTransition(from: TaskState, to: TaskState): void {
  if (!canTransitionTask(from, to)) {
    throw new Error(`Invalid task transition: ${from} -> ${to}`);
  }
}

export function assertTaskStateRequirements(input: {
  state: TaskState;
  waitingOnType?: string | null;
  blockedReason?: string | null;
  heldReason?: string | null;
  supersededByTaskId?: string | null;
  completionEvidenceId?: string | null;
}): void {
  if (input.state === "WAITING" && !input.waitingOnType) {
    throw new Error("WAITING tasks require waitingOnType");
  }
  if (input.state === "BLOCKED" && !input.blockedReason) {
    throw new Error("BLOCKED tasks require blockedReason");
  }
  if (input.state === "HELD" && !input.heldReason) {
    throw new Error("HELD tasks require heldReason");
  }
  if (input.state === "SUPERSEDED" && !input.supersededByTaskId) {
    throw new Error("SUPERSEDED tasks require supersededByTaskId");
  }
  if (input.state === "COMPLETED" && !input.completionEvidenceId) {
    throw new Error("COMPLETED tasks require completion evidence");
  }
}

export const requestAccessModes = [
  "NORMAL",
  "ACCESS_CATALOG",
  "PORTFOLIO",
  "SYSTEM_JOB",
] as const;

export type RequestAccessMode = (typeof requestAccessModes)[number];