import type { ObjectId } from "mongodb";
import type { AssetCriticality, AssetType, ScanFrequency, VerificationMethod } from "@asm/contracts/assets";
import type { FindingConfidence, FindingSeverity, FindingStatus } from "@asm/contracts/findings";
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

export interface AssetDocument {
  type: AssetType;
  value: string;
  displayName?: string;
  criticality: AssetCriticality;
  tags: string[];
  ownershipStatus: "pending" | "verified" | "failed";
  verifiedAt?: Date;
  lastScanAt?: Date;
  nextScanAt?: Date;
  scanFrequency: ScanFrequency;
  createdBy: ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

export interface OwnershipChallengeDocument {
  assetId: ObjectId;
  method: VerificationMethod;
  tokenHash: string;
  verificationValue: string;
  recordName: string;
  expiresAt: Date;
  createdAt: Date;
}

export interface ScanRunDocument {
  assetId: ObjectId;
  status: "queued" | "running" | "completed" | "failed";
  workflowRunId?: string;
  error?: string;
  observationCount: number;
  createdBy: ObjectId;
  createdAt: Date;
  startedAt?: Date;
  completedAt?: Date;
}

export interface ObservationDocument {
  assetId: ObjectId;
  scanRunId: ObjectId;
  type: "dns" | "tls" | "http" | "technology" | "certificates" | "rdap";
  data: Record<string, unknown>;
  observedAt: Date;
}

export interface FindingDocument {
  assetId: ObjectId;
  scanRunId: ObjectId;
  fingerprint: string;
  ruleId: string;
  title: string;
  description: string;
  remediation: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  status: FindingStatus;
  riskScore: number;
  riskFactors: { severity: number; confidence: number; exposure: number; criticality: number; exploitability: number };
  evidence: Record<string, unknown>;
  firstSeenAt: Date;
  lastSeenAt: Date;
  resolvedAt?: Date;
  acceptedUntil?: Date;
  recurrenceCount: number;
  slaDueAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface FindingEventDocument {
  findingId: ObjectId;
  actorId?: ObjectId;
  type: "created" | "status_changed" | "comment" | "reopened" | "resolved";
  message: string;
  fromStatus?: FindingStatus;
  toStatus?: FindingStatus;
  createdAt: Date;
}

export interface RiskSnapshotDocument {
  scanRunId: ObjectId;
  assetId: ObjectId;
  riskScore: number;
  openCount: number;
  severityCounts: Record<string, number>;
  createdAt: Date;
}

export async function collections() {
  const db = await getDatabase();
  return {
    admins: db.collection<AdminDocument>("admins"),
    sessions: db.collection<SessionDocument>("sessions"),
    auditLogs: db.collection<AuditLogDocument>("auditLogs"),
    assets: db.collection<AssetDocument>("assets"),
    ownershipChallenges: db.collection<OwnershipChallengeDocument>("ownershipChallenges"),
    scanRuns: db.collection<ScanRunDocument>("scanRuns"),
    observations: db.collection<ObservationDocument>("observations"),
    findings: db.collection<FindingDocument>("findings"),
    findingEvents: db.collection<FindingEventDocument>("findingEvents"),
    riskSnapshots: db.collection<RiskSnapshotDocument>("riskSnapshots"),
  };
}

export async function ensureIndexes() {
  const { admins, sessions, auditLogs, assets, ownershipChallenges, scanRuns, observations, findings, findingEvents, riskSnapshots } = await collections();
  await Promise.all([
    admins.createIndex({ email: 1 }, { unique: true, name: "admin_email_unique" }),
    sessions.createIndex({ tokenHash: 1 }, { unique: true, name: "session_token_unique" }),
    sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0, name: "session_expiry_ttl" }),
    sessions.createIndex({ adminId: 1 }, { name: "session_admin" }),
    auditLogs.createIndex({ createdAt: -1 }, { name: "audit_created_at" }),
    assets.createIndex({ type: 1, value: 1 }, { unique: true, name: "asset_type_value_unique" }),
    assets.createIndex({ ownershipStatus: 1, updatedAt: -1 }, { name: "asset_ownership_updated" }),
    assets.createIndex({ ownershipStatus: 1, nextScanAt: 1 }, { name: "asset_scheduling" }),
    ownershipChallenges.createIndex({ assetId: 1, expiresAt: -1 }, { name: "challenge_asset_expiry" }),
    ownershipChallenges.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0, name: "challenge_expiry_ttl" }),
    scanRuns.createIndex({ assetId: 1, createdAt: -1 }, { name: "scan_asset_created" }),
    scanRuns.createIndex({ status: 1, createdAt: -1 }, { name: "scan_status_created" }),
    observations.createIndex({ assetId: 1, observedAt: -1 }, { name: "observation_asset_observed" }),
    observations.createIndex({ scanRunId: 1 }, { name: "observation_scan" }),
    findings.createIndex({ fingerprint: 1 }, { unique: true, name: "finding_fingerprint_unique" }),
    findings.createIndex({ status: 1, severity: 1, lastSeenAt: -1 }, { name: "finding_status_severity_seen" }),
    findings.createIndex({ assetId: 1, status: 1 }, { name: "finding_asset_status" }),
    findings.createIndex({ slaDueAt: 1, status: 1 }, { name: "finding_sla" }),
    findingEvents.createIndex({ findingId: 1, createdAt: -1 }, { name: "finding_event_timeline" }),
    riskSnapshots.createIndex({ scanRunId: 1 }, { unique: true, name: "risk_snapshot_scan_unique" }),
    riskSnapshots.createIndex({ createdAt: -1 }, { name: "risk_snapshot_created" }),
  ]);
}
