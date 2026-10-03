import { z } from "zod";

export const findingSeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export const findingStatusSchema = z.enum(["open", "investigating", "resolved", "accepted", "false_positive"]);
export const findingConfidenceSchema = z.enum(["high", "medium", "low"]);

export const updateFindingSchema = z.object({
  findingId: z.string().regex(/^[a-f\d]{24}$/i),
  status: findingStatusSchema,
  acceptedUntil: z.coerce.date().optional(),
  comment: z.string().trim().max(2_000).optional(),
});

export const addFindingCommentSchema = z.object({
  findingId: z.string().regex(/^[a-f\d]{24}$/i),
  comment: z.string().trim().min(1).max(2_000),
});

export const bulkFindingUpdateSchema = z.object({
  findingIds: z.array(z.string().regex(/^[a-f\d]{24}$/i)).min(1).max(100),
  status: findingStatusSchema,
});

export type FindingSeverity = z.infer<typeof findingSeveritySchema>;
export type FindingStatus = z.infer<typeof findingStatusSchema>;
export type FindingConfidence = z.infer<typeof findingConfidenceSchema>;
