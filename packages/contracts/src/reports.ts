import { z } from "zod";

export const reportKindSchema = z.enum(["executive", "technical", "asset_inventory"]);
export const reportFormatSchema = z.enum(["pdf", "csv"]);
export const createReportSchema = z.object({ kind: reportKindSchema, format: reportFormatSchema });

export type ReportKind = z.infer<typeof reportKindSchema>;
export type ReportFormat = z.infer<typeof reportFormatSchema>;
