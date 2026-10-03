import { z } from "zod";

export const scanRequestSchema = z.object({
  assetId: z.string().regex(/^[a-f\d]{24}$/i),
});

export const scanWorkflowPayloadSchema = z.object({
  scanRunId: z.string().regex(/^[a-f\d]{24}$/i),
  assetId: z.string().regex(/^[a-f\d]{24}$/i),
});

export type ScanWorkflowPayload = z.infer<typeof scanWorkflowPayloadSchema>;
