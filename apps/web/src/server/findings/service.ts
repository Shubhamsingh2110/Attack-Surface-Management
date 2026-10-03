import "server-only";
import { createHash } from "node:crypto";
import { ObjectId, type Filter } from "mongodb";
import type { FindingDocument } from "@asm/database";
import { collections, ensureIndexes } from "@asm/database";
import type { FindingStatus } from "@asm/contracts/findings";
import { calculateRisk, detectFindings, slaDays } from "@asm/risk-engine";
import { notifyNewFinding } from "@/server/integrations/service";

function fingerprint(assetId: string, ruleId: string, key: string) { return createHash("sha256").update(`${assetId}:${ruleId}:${key}`).digest("hex"); }

export async function syncFindingsForScan(scanRunId: string, assetId: string) {
  await ensureIndexes();
  const { assets, observations, findings, findingEvents, riskSnapshots } = await collections();
  const assetObjectId = new ObjectId(assetId);
  const scanObjectId = new ObjectId(scanRunId);
  const asset = await assets.findOne({ _id: assetObjectId });
  if (!asset) throw new Error("Asset not found for finding evaluation.");
  const [evidence, knownAssets] = await Promise.all([
    observations.find({ scanRunId: scanObjectId }).toArray(),
    assets.find({}, { projection: { value: 1 } }).toArray(),
  ]);
  const candidates = detectFindings({ assetValue: asset.value, knownAssets: knownAssets.map((item) => item.value), observations: evidence.map((item) => ({ type: item.type, data: item.data })) });
  const now = new Date();
  const seen: string[] = [];
  const completeEvidence = evidence.every((item) => item.data.status !== "unavailable");
  const notifications: Array<{ title: string; severity: string; riskScore: number; asset: string }> = [];

  for (const candidate of candidates) {
    const value = fingerprint(assetId, candidate.ruleId, candidate.key);
    seen.push(value);
    const risk = calculateRisk(candidate.severity, candidate.confidence, asset.criticality, candidate.exploitability);
    const existing = await findings.findOne({ fingerprint: value });
    if (!existing) {
      const result = await findings.insertOne({
        assetId: assetObjectId, scanRunId: scanObjectId, fingerprint: value, ruleId: candidate.ruleId,
        title: candidate.title, description: candidate.description, remediation: candidate.remediation,
        severity: candidate.severity, confidence: candidate.confidence, status: "open", ...risk,
        evidence: candidate.evidence, firstSeenAt: now, lastSeenAt: now, recurrenceCount: 0,
        slaDueAt: new Date(now.getTime() + slaDays(candidate.severity) * 86_400_000), createdAt: now, updatedAt: now,
      });
      await findingEvents.insertOne({ findingId: result.insertedId, type: "created", message: "Finding created by passive discovery.", createdAt: now });
      if (candidate.severity === "critical" || candidate.severity === "high") notifications.push({ title: candidate.title, severity: candidate.severity, riskScore: risk.riskScore, asset: asset.value });
      continue;
    }
    const shouldReopen = existing.status === "resolved" || (existing.status === "accepted" && existing.acceptedUntil && existing.acceptedUntil <= now);
    await findings.updateOne({ _id: existing._id }, {
      $set: { scanRunId: scanObjectId, lastSeenAt: now, updatedAt: now, evidence: candidate.evidence, severity: candidate.severity, confidence: candidate.confidence, ...risk, ...(shouldReopen ? { status: "open" as const, slaDueAt: new Date(now.getTime() + slaDays(candidate.severity) * 86_400_000) } : {}) },
      ...(shouldReopen ? { $inc: { recurrenceCount: 1 } } : {}),
      ...(shouldReopen ? { $unset: { resolvedAt: "", acceptedUntil: "" } } : {}),
    });
    if (shouldReopen) await findingEvents.insertOne({ findingId: existing._id, type: "reopened", message: "Finding observed again and reopened.", fromStatus: existing.status, toStatus: "open", createdAt: now });
  }

  const stale = completeEvidence ? await findings.find({ assetId: assetObjectId, status: { $in: ["open", "investigating", "accepted"] }, ...(seen.length ? { fingerprint: { $nin: seen } } : {}) }).toArray() : [];
  for (const finding of stale) {
    await findings.updateOne({ _id: finding._id }, { $set: { status: "resolved", resolvedAt: now, updatedAt: now } });
    await findingEvents.insertOne({ findingId: finding._id, type: "resolved", message: "Finding was not observed in the latest completed scan.", fromStatus: finding.status, toStatus: "resolved", createdAt: now });
  }
  const activeForAsset = await findings.find({ assetId: assetObjectId, status: { $in: ["open", "investigating"] } }).toArray();
  const severityCounts = activeForAsset.reduce<Record<string, number>>((counts, finding) => ({ ...counts, [finding.severity]: (counts[finding.severity] ?? 0) + 1 }), {});
  const snapshotRisk = activeForAsset.length ? Math.round(activeForAsset.slice().sort((a, b) => b.riskScore - a.riskScore).slice(0, 5).reduce((sum, finding) => sum + finding.riskScore, 0) / Math.min(activeForAsset.length, 5)) : 0;
  await riskSnapshots.updateOne({ scanRunId: scanObjectId }, { $set: { scanRunId: scanObjectId, assetId: assetObjectId, riskScore: snapshotRisk, openCount: activeForAsset.length, severityCounts, createdAt: now } }, { upsert: true });
  await Promise.allSettled(notifications.map(notifyNewFinding));
  return { detected: candidates.length, resolved: stale.length };
}

async function expireRiskAcceptances() {
  const { findings, findingEvents } = await collections();
  const now = new Date();
  const expired = await findings.find({ status: "accepted", acceptedUntil: { $lte: now } }).limit(100).toArray();
  for (const finding of expired) {
    await findings.updateOne({ _id: finding._id }, { $set: { status: "open", updatedAt: now, slaDueAt: new Date(now.getTime() + slaDays(finding.severity) * 86_400_000) }, $unset: { acceptedUntil: "" } });
    await findingEvents.insertOne({ findingId: finding._id, type: "reopened", message: "Risk acceptance expired; finding reopened.", fromStatus: "accepted", toStatus: "open", createdAt: now });
  }
}

export async function listFindings(filters: { status?: string; severity?: string; assetId?: string; query?: string } = {}) {
  await expireRiskAcceptances();
  const { findings, assets } = await collections();
  const filter: Filter<FindingDocument> = {};
  if (filters.status && ["open", "investigating", "resolved", "accepted", "false_positive"].includes(filters.status)) filter.status = filters.status as FindingStatus;
  if (filters.severity && ["critical", "high", "medium", "low", "info"].includes(filters.severity)) filter.severity = filters.severity as FindingDocument["severity"];
  if (filters.assetId && ObjectId.isValid(filters.assetId)) filter.assetId = new ObjectId(filters.assetId);
  if (filters.query) {
    const escaped = filters.query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const matchingAssets = await assets.find({ value: { $regex: escaped, $options: "i" } }, { projection: { _id: 1 } }).limit(100).toArray();
    filter.$or = [
      { title: { $regex: escaped, $options: "i" } },
      { description: { $regex: escaped, $options: "i" } },
      { assetId: { $in: matchingAssets.map((asset) => asset._id) } },
    ];
  }
  const rows = await findings.find(filter).sort({ riskScore: -1, lastSeenAt: -1 }).limit(500).toArray();
  const assetIds = [...new Set(rows.map((finding) => finding.assetId.toHexString()))];
  const assetRows = assetIds.length ? await assets.find({ _id: { $in: assetIds.map((id) => new ObjectId(id)) } }).toArray() : [];
  const assetValues = new Map(assetRows.map((asset) => [asset._id.toHexString(), asset.value]));
  return rows.map((finding) => ({ ...finding, _id: finding._id.toHexString(), assetValue: assetValues.get(finding.assetId.toHexString()) ?? "Unknown asset" }));
}

export async function listFindingAssets() {
  const { findings, assets } = await collections();
  const ids = await findings.distinct("assetId");
  if (!ids.length) return [];
  const rows = await assets.find({ _id: { $in: ids } }, { projection: { value: 1 } }).sort({ value: 1 }).toArray();
  return rows.map((asset) => ({ id: asset._id.toHexString(), value: asset.value }));
}

export async function getFindingDetails(id: string) {
  if (!ObjectId.isValid(id)) return null;
  const { findings, assets, findingEvents } = await collections();
  const finding = await findings.findOne({ _id: new ObjectId(id) });
  if (!finding) return null;
  const [asset, events] = await Promise.all([assets.findOne({ _id: finding.assetId }), findingEvents.find({ findingId: finding._id }).sort({ createdAt: -1 }).toArray()]);
  return { ...finding, _id: finding._id.toHexString(), assetValue: asset?.value ?? "Unknown asset", events: events.map((event) => ({ ...event, _id: event._id.toHexString() })) };
}

export async function updateFinding(input: { findingId: string; status: FindingStatus; acceptedUntil?: Date; comment?: string; actorId: string }) {
  const { findings, findingEvents } = await collections();
  const _id = new ObjectId(input.findingId);
  const finding = await findings.findOne({ _id });
  if (!finding) throw new Error("Finding not found.");
  if (input.status === "accepted" && (!input.acceptedUntil || input.acceptedUntil <= new Date())) throw new Error("Risk acceptance requires a future expiration date.");
  const now = new Date();
  const unset: Record<string, ""> = {};
  if (input.status !== "accepted") unset.acceptedUntil = "";
  if (input.status !== "resolved") unset.resolvedAt = "";
  await findings.updateOne({ _id }, { $set: { status: input.status, updatedAt: now, ...(input.status === "resolved" ? { resolvedAt: now } : {}), ...(input.status === "accepted" ? { acceptedUntil: input.acceptedUntil } : {}) }, ...(Object.keys(unset).length ? { $unset: unset } : {}) });
  await findingEvents.insertOne({ findingId: _id, actorId: new ObjectId(input.actorId), type: "status_changed", message: input.comment || `Status changed to ${input.status.replace("_", " ")}.`, fromStatus: finding.status, toStatus: input.status, createdAt: now });
}

export async function addFindingComment(findingId: string, comment: string, actorId: string) {
  const { findings, findingEvents } = await collections();
  const _id = new ObjectId(findingId);
  if (!await findings.findOne({ _id })) throw new Error("Finding not found.");
  await findingEvents.insertOne({ findingId: _id, actorId: new ObjectId(actorId), type: "comment", message: comment, createdAt: new Date() });
}

export async function bulkUpdateFindings(ids: string[], status: FindingStatus, actorId: string) {
  for (const id of ids) await updateFinding({ findingId: id, status, actorId, ...(status === "accepted" ? { acceptedUntil: new Date(Date.now() + 30 * 86_400_000) } : {}) });
}

export async function getDashboardMetrics() {
  await expireRiskAcceptances();
  const { assets, findings, scanRuns, riskSnapshots } = await collections();
  const active = { $in: ["open", "investigating"] as FindingStatus[] };
  const [assetCount, verifiedCount, openCount, overdueCount, runningScans, severityRows, topFindings, trend] = await Promise.all([
    assets.countDocuments(), assets.countDocuments({ ownershipStatus: "verified" }), findings.countDocuments({ status: active }),
    findings.countDocuments({ status: active, slaDueAt: { $lt: new Date() } }), scanRuns.countDocuments({ status: { $in: ["queued", "running"] } }),
    findings.aggregate<{ _id: string; count: number }>([{ $match: { status: active } }, { $group: { _id: "$severity", count: { $sum: 1 } } }]).toArray(),
    findings.find({ status: active }).sort({ riskScore: -1 }).limit(5).toArray(),
    riskSnapshots.find().sort({ createdAt: -1 }).limit(12).toArray(),
  ]);
  const riskScore = topFindings.length ? Math.round(topFindings.reduce((sum, item) => sum + item.riskScore, 0) / topFindings.length) : 0;
  return { assetCount, verifiedCount, openCount, overdueCount, runningScans, riskScore, severity: Object.fromEntries(severityRows.map((row) => [row._id, row.count])), topFindings, trend: trend.reverse() };
}
