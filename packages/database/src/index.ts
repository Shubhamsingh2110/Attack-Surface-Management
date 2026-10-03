import type { ObjectId } from "mongodb";
import { getDatabase } from "./mongodb";

export { getDatabase } from "./mongodb";

export interface AdminDocument {
  email: string;
  name: string;
  passwordHash: string;
  role: "admin";
  isActive: boolean;
  failedLoginAttempts: number;
  lockedUntil?: Date;
  lastLoginAt?: Date;
  passwordChangedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface SessionDocument {
  adminId: ObjectId;
  tokenHash: string;
  createdAt: Date;
  expiresAt: Date;
  userAgent?: string;
}

export interface AuditLogDocument {
  event: string;
  actorId?: ObjectId;
  outcome: "success" | "failure";
  metadata?: Record<string, string | number | boolean>;
  createdAt: Date;
}

export async function collections() {
  const db = await getDatabase();
  return {
    admins: db.collection<AdminDocument>("admins"),
    sessions: db.collection<SessionDocument>("sessions"),
    auditLogs: db.collection<AuditLogDocument>("auditLogs"),
  };
}

export async function ensureIndexes() {
  const { admins, sessions, auditLogs } = await collections();
  await Promise.all([
    admins.createIndex({ email: 1 }, { unique: true, name: "admin_email_unique" }),
    sessions.createIndex({ tokenHash: 1 }, { unique: true, name: "session_token_unique" }),
    sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0, name: "session_expiry_ttl" }),
    sessions.createIndex({ adminId: 1 }, { name: "session_admin" }),
    auditLogs.createIndex({ createdAt: -1 }, { name: "audit_created_at" }),
  ]);
}
