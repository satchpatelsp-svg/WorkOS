import { z } from "zod";

const uuidSchema = z.string().uuid();

export const normalRequestContextSchema = z.object({
  mode: z.literal("NORMAL"),
  userId: uuidSchema,
  tenantId: uuidSchema,
  workspaceId: uuidSchema,
  membershipContextVersion: z.number().int().positive(),
  assignmentId: uuidSchema.optional(),
  assignmentContextVersion: z.number().int().positive().optional(),
  representedPrincipalId: uuidSchema.optional(),
});

export const accessCatalogContextSchema = z.object({
  mode: z.literal("ACCESS_CATALOG"),
  userId: uuidSchema,
});

export const systemJobContextSchema = z.object({
  mode: z.literal("SYSTEM_JOB"),
  systemJobId: uuidSchema,
  claimToken: uuidSchema,
  tenantId: uuidSchema,
  workspaceId: uuidSchema,
  resourceId: uuidSchema.optional(),
  jobType: z.string().min(1),
});

export type NormalRequestContext = z.infer<typeof normalRequestContextSchema>;
export type AccessCatalogContext = z.infer<typeof accessCatalogContextSchema>;
export type SystemJobContext = z.infer<typeof systemJobContextSchema>;

export type RequestContext =
  | NormalRequestContext
  | AccessCatalogContext
  | SystemJobContext;