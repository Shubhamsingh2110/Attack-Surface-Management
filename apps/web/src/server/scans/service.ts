import "server-only";
import { ObjectId } from "mongodb";
import { Client } from "@upstash/workflow";
import { collections } from "@asm/database";
import { scanCertificateTransparency, scanDns, scanHttp, scanRdap, scanTls } from "@asm/scanner-core";
import { syncFindingsForScan } from "@/server/findings/service";

export async function createScanRun(assetId: string, adminId: string) {
  const { assets, scanRuns } = await collections();
  const asset = await assets.findOne({ _id: new ObjectId(assetId) });
  if (!asset || asset.ownershipStatus !== "verified") throw new Error("Only verified assets can be scanned.");
  if (asset.type !== "domain" && asset.type !== "subdomain") throw new Error("Passive scanning currently supports domain assets only.");
  if (await scanRuns.countDocuments({ status: { $in: ["queued", "running"] } }) >= 5) throw new Error("Scan concurrency limit reached. Try again after an active scan finishes.");
  if (await scanRuns.findOne({ assetId: asset._id, status: { $in: ["queued", "running"] } })) throw new Error("This asset already has an active scan.");
  const result = await scanRuns.insertOne({ assetId: asset._id, status: "queued", observationCount: 0, createdBy: new ObjectId(adminId), createdAt: new Date() });
  const token = process.env.QSTASH_TOKEN;
  const appUrl = process.env.APP_URL?.replace(/\/$/, "");
  if (!token || !appUrl) {
    await scanRuns.updateOne({ _id: result.insertedId }, { $set: { status: "failed", error: "Configure QSTASH_TOKEN and APP_URL to run scans.", completedAt: new Date() } });
    throw new Error("Scanning requires QSTASH_TOKEN and APP_URL.");
  }
  const client = new Client({ token });
  const workflow = await client.trigger({
    url: `${appUrl}/api/workflows/passive-scan`,
    body: { scanRunId: result.insertedId.toHexString(), assetId },
    workflowRunId: `scan-${result.insertedId.toHexString()}`,
    retries: 3,
  });
  await scanRuns.updateOne({ _id: result.insertedId }, { $set: { workflowRunId: workflow.workflowRunId } });
  return result.insertedId;
}

export async function startScan(scanRunId: string) {
  const { scanRuns } = await collections();
  await scanRuns.updateOne({ _id: new ObjectId(scanRunId), status: "queued" }, { $set: { status: "running", startedAt: new Date() } });
}

export async function scanStep(scanRunId: string, assetId: string, type: "dns" | "tls" | "http" | "certificates" | "rdap") {
  const { assets, observations } = await collections();
  const assetObjectId = new ObjectId(assetId);
  const scanObjectId = new ObjectId(scanRunId);
  const asset = await assets.findOne({ _id: assetObjectId, ownershipStatus: "verified" });
  if (!asset) throw new Error("Verified asset not found.");
  const data = type === "dns" ? await scanDns(asset.value) : type === "tls" ? await scanTls(asset.value) : type === "http" ? await scanHttp(asset.value) : type === "certificates" ? await scanCertificateTransparency(asset.value) : await scanRdap(asset.value);
  await observations.updateOne({ scanRunId: scanObjectId, type }, { $set: { assetId: assetObjectId, scanRunId: scanObjectId, type, data, observedAt: new Date() } }, { upsert: true });
  return data;
}

export async function completeScan(scanRunId: string, assetId: string) {
  const { scanRuns, observations, assets } = await collections();
  const scanObjectId = new ObjectId(scanRunId);
  const now = new Date();
  const observationCount = await observations.countDocuments({ scanRunId: scanObjectId });
  await syncFindingsForScan(scanRunId, assetId);
  await scanRuns.updateOne({ _id: scanObjectId }, { $set: { status: "completed", completedAt: now, observationCount } });
  const asset = await assets.findOne({ _id: new ObjectId(assetId) });
  const nextScanAt = asset?.scanFrequency === "daily" ? new Date(now.getTime() + 86_400_000) : asset?.scanFrequency === "weekly" ? new Date(now.getTime() + 7 * 86_400_000) : undefined;
  await assets.updateOne({ _id: new ObjectId(assetId) }, nextScanAt ? { $set: { lastScanAt: now, nextScanAt, updatedAt: now } } : { $set: { lastScanAt: now, updatedAt: now }, $unset: { nextScanAt: "" } });
}

export async function queueDueScans() {
  const { assets } = await collections();
  const now = new Date();
  const due = await assets.find({ ownershipStatus: "verified", scanFrequency: { $in: ["daily", "weekly"] }, $or: [{ nextScanAt: { $lte: now } }, { nextScanAt: { $exists: false } }] }).limit(20).toArray();
  const results = await Promise.allSettled(due.map((asset) => createScanRun(asset._id.toHexString(), asset.createdBy.toHexString())));
  return { queued: results.filter((result) => result.status === "fulfilled").length, failed: results.filter((result) => result.status === "rejected").length };
}

export async function failScan(scanRunId: string, error: unknown) {
  const { scanRuns } = await collections();
  await scanRuns.updateOne({ _id: new ObjectId(scanRunId) }, { $set: { status: "failed", completedAt: new Date(), error: error instanceof Error ? error.message.slice(0, 500) : "Scan failed" } });
}

export async function listScanRuns() {
  const { scanRuns, assets } = await collections();
  const runs = await scanRuns.find().sort({ createdAt: -1 }).limit(100).toArray();
  return Promise.all(runs.map(async (run) => ({ ...run, _id: run._id.toHexString(), assetValue: (await assets.findOne({ _id: run.assetId }))?.value ?? "Unknown asset" })));
}

export async function getScanRunDetails(scanRunId: string) {
  if (!ObjectId.isValid(scanRunId)) return null;
  const { scanRuns, assets, observations } = await collections();
  const run = await scanRuns.findOne({ _id: new ObjectId(scanRunId) });
  if (!run) return null;
  const asset = await assets.findOne({ _id: run.assetId });
  const evidence = await observations.find({ scanRunId: run._id }).sort({ type: 1 }).toArray();
  return { ...run, _id: run._id.toHexString(), assetValue: asset?.value ?? "Unknown asset", observations: evidence.map((item) => ({ ...item, _id: item._id.toHexString() })) };
}
