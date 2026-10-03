import { z } from "zod";

export const assetTypeSchema = z.enum(["domain", "subdomain", "ip", "cidr"]);
export const assetCriticalitySchema = z.enum(["low", "medium", "high", "critical"]);
export const verificationMethodSchema = z.enum(["dns_txt", "http_file"]);
export const scanFrequencySchema = z.enum(["manual", "daily", "weekly"]);

export const createAssetSchema = z.object({
  type: assetTypeSchema,
  value: z.string().trim().min(1).max(253),
  displayName: z.string().trim().max(100).optional(),
  criticality: assetCriticalitySchema.default("medium"),
  tags: z.array(z.string().trim().min(1).max(32)).max(20).default([]),
  scanFrequency: scanFrequencySchema.default("manual"),
});

export const createChallengeSchema = z.object({
  assetId: z.string().regex(/^[a-f\d]{24}$/i),
  method: verificationMethodSchema,
});

export const assetIdSchema = z.string().regex(/^[a-f\d]{24}$/i);

export type AssetType = z.infer<typeof assetTypeSchema>;
export type AssetCriticality = z.infer<typeof assetCriticalitySchema>;
export type VerificationMethod = z.infer<typeof verificationMethodSchema>;
export type ScanFrequency = z.infer<typeof scanFrequencySchema>;
