import type { ObjectId } from "mongodb";
import { collections } from "@asm/database";

export async function writeAuditLog(input: {
  event: string;
  actorId?: ObjectId;
  outcome: "success" | "failure";
  metadata?: Record<string, string | number | boolean>;
}) {
  try {
    const { auditLogs } = await collections();
    await auditLogs.insertOne({ ...input, createdAt: new Date() });
  } catch (error) {
    console.error(JSON.stringify({ level: "error", message: "audit_log_write_failed", event: input.event, error: error instanceof Error ? error.message : "unknown" }));
  }
}
