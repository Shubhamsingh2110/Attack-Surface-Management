import "server-only";
import { ObjectId } from "mongodb";
import { after } from "next/server";
import { Client } from "@upstash/workflow";
import { collections } from "@asm/database";
import { scanCertificateTransparency, scanDns, scanHttp, scanRdap, scanTls } from "@asm/scanner-core";
import { syncFindingsForScan } from "@/server/findings/service";

const STALE_QUEUED_MS = 5 * 60 * 1_000;
const STALE_RUNNING_MS = 15 * 60 * 1_000;

async function failStaleScans() {
  const { scanRuns } = await collections();
  const now = new Date();
  await Promise.all([
    scanRuns.updateMany(
      { status: "queued", createdAt: { $lt: new Date(now.getTime() - STALE_QUEUED_MS) } },
      { $set: { status: "failed", completedAt: now, error: "Scan dispatch timed out before the workflow started. Retry the scan." } },
    ),
    scanRuns.updateMany(
      { status: "running", startedAt: { $lt: new Date(now.getTime() - STALE_RUNNING_MS) } },
      { $set: { status: "failed", completedAt: now, error: "Scan execution timed out. Retry the scan." } },
    ),
  ]);
}

async function runPassiveScanDirectly(scanRunId: string, assetId: string) {
  try {
    await startScan(scanRunId);
    await Promise.all((["dns", "certificates", "rdap", "tls", "http"] as const).map((step) => scanStep(scanRunId, assetId, step)));
    await completeScan(scanRunId, assetId);
  } catch (error) {
    await failScan(scanRunId, error);
    throw error;
  }
}

export async function createScanRun(assetId: string, adminId: string) {
  await failStaleScans();
  const { assets, scanRuns } = await collections();
  const asset = await assets.findOne({ _id: new ObjectId(assetId) });
  if (!asset) throw new Error("Asset not found.");
  if (asset.type !== "domain" && asset.type !== "subdomain") throw new Error("Passive scanning currently supports domain assets only.");
  if (await scanRuns.countDocuments({ status: { $in: ["queued", "running"] } }) >= 5) throw new Error("Scan concurrency limit reached. Try again after an active scan finishes.");
  if (await scanRuns.findOne({ assetId: asset._id, status: { $in: ["queued", "running"] } })) throw new Error("This asset already has an active scan.");
  const result = await scanRuns.insertOne({ assetId: asset._id, status: "queued", observationCount: 0, createdBy: new ObjectId(adminId), createdAt: new Date() });
  const token = process.env.QSTASH_TOKEN;
  const appUrl = process.env.APP_URL?.replace(/\/$/, "");
  if (!appUrl) {
    await scanRuns.updateOne({ _id: result.insertedId }, { $set: { status: "failed", error: "Configure QSTASH_TOKEN and APP_URL to run scans.", completedAt: new Date() } });
    throw new Error("Scanning requires APP_URL.");
  }
  let url: URL;
  try { url = new URL(appUrl); }
  catch {
    await scanRuns.updateOne({ _id: result.insertedId }, { $set: { status: "failed", error: "APP_URL is invalid.", completedAt: new Date() } });
    throw new Error("APP_URL must be a valid absolute URL.");
  }
  if (["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
    after(async () => {
      try { await runPassiveScanDirectly(result.insertedId.toHexString(), assetId); }
      catch (error) { console.error(JSON.stringify({ level: "error", event: "local_passive_scan_failed", scanRunId: result.insertedId.toHexString(), error: error instanceof Error ? error.message : "unknown" })); }
    });
    return result.insertedId;
  }
  if (url.protocol !== "https:" || !token) {
    await scanRuns.updateOne({ _id: result.insertedId }, { $set: { status: "failed", error: "Production scanning requires an HTTPS APP_URL and QSTASH_TOKEN.", completedAt: new Date() } });
    throw new Error("Production scanning requires an HTTPS APP_URL and QSTASH_TOKEN.");
  }
  try {
    const client = new Client({ token });
    const workflow = await client.trigger({
      url: `${appUrl}/api/workflows/passive-scan`, body: { scanRunId: result.insertedId.toHexString(), assetId },
      workflowRunId: `scan-${result.insertedId.toHexString()}`, retries: 3,
    });
    await scanRuns.updateOne({ _id: result.insertedId }, { $set: { workflowRunId: workflow.workflowRunId } });
  } catch (error) {
    await failScan(result.insertedId.toHexString(), error);
    throw new Error(`Unable to dispatch scan workflow: ${error instanceof Error ? error.message : "unknown error"}`);
  }
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
  const asset = await assets.findOne({ _id: assetObjectId });
  if (!asset) throw new Error("Asset not found.");
  let data: Record<string, unknown>;
  try {
    data = type === "dns" ? await scanDns(asset.value) : type === "tls" ? await scanTls(asset.value) : type === "http" ? await scanHttp(asset.value) : type === "certificates" ? await scanCertificateTransparency(asset.value) : await scanRdap(asset.value);
  } catch (error) {
    data = { status: "unavailable", error: error instanceof Error ? error.message.slice(0, 500) : `${type} provider unavailable` };
  }
  await observations.updateOne({ scanRunId: scanObjectId, type }, { $set: { assetId: assetObjectId, scanRunId: scanObjectId, type, data, observedAt: new Date() } }, { upsert: true });
  if (type === "dns") {
    const emailData = data.status === "unavailable" ? data : (data.emailSecurity && typeof data.emailSecurity === "object" ? data.emailSecurity as Record<string, unknown> : { spfRecords: [], dmarcRecords: [] });
    await observations.updateOne({ scanRunId: scanObjectId, type: "email_security" }, { $set: { assetId: assetObjectId, scanRunId: scanObjectId, type: "email_security", data: emailData, observedAt: new Date() } }, { upsert: true });
  }
  if (type === "http") {
    const technologyData = data.status === "unavailable" ? data : { technologies: data.technologies ?? [], technologyDetails: data.technologyDetails ?? [], vulnerabilityAssessment: "Detected versions are evaluated conservatively by the findings engine." };
    await observations.updateOne({ scanRunId: scanObjectId, type: "technology" }, { $set: { assetId: assetObjectId, scanRunId: scanObjectId, type: "technology", data: technologyData, observedAt: new Date() } }, { upsert: true });
  }
  if (type === "tls") {
    const certificateData = data.status === "unavailable" ? data : { authorized: data.authorized, authorizationError: data.authorizationError, protocol: data.protocol, cipher: data.cipher, subject: data.subject, issuer: data.issuer, validFrom: data.validFrom, validTo: data.validTo, subjectAltName: data.subjectAltName, fingerprint256: data.fingerprint256, serialNumber: data.serialNumber, keyBits: data.keyBits };
    await observations.updateOne({ scanRunId: scanObjectId, type: "ssl_certificate" }, { $set: { assetId: assetObjectId, scanRunId: scanObjectId, type: "ssl_certificate", data: certificateData, observedAt: new Date() } }, { upsert: true });
  }
  return data;
}

export async function completeScan(scanRunId: string, assetId: string) {
  const { scanRuns, observations, assets } = await collections();
  const scanObjectId = new ObjectId(scanRunId);
  const now = new Date();
  const observationCount = await observations.countDocuments({ scanRunId: scanObjectId });
  const unavailable = await observations.countDocuments({ scanRunId: scanObjectId, "data.status": "unavailable" });
  await syncFindingsForScan(scanRunId, assetId);
  await scanRuns.updateOne({ _id: scanObjectId }, { $set: { status: "completed", completedAt: now, observationCount, ...(unavailable ? { warning: `Completed with ${unavailable} unavailable passive source${unavailable === 1 ? "" : "s"}.` } : {}) }, ...(unavailable ? {} : { $unset: { warning: "" } }) });
  const asset = await assets.findOne({ _id: new ObjectId(assetId) });
  const nextScanAt = asset?.scanFrequency === "daily" ? new Date(now.getTime() + 86_400_000) : asset?.scanFrequency === "weekly" ? new Date(now.getTime() + 7 * 86_400_000) : undefined;
  await assets.updateOne({ _id: new ObjectId(assetId) }, nextScanAt ? { $set: { lastScanAt: now, nextScanAt, updatedAt: now } } : { $set: { lastScanAt: now, updatedAt: now }, $unset: { nextScanAt: "" } });
}

export async function queueDueScans() {
  const { assets } = await collections();
  const now = new Date();
  const due = await assets.find({ type: { $in: ["domain", "subdomain"] }, scanFrequency: { $in: ["daily", "weekly"] }, $or: [{ nextScanAt: { $lte: now } }, { nextScanAt: { $exists: false } }] }).limit(20).toArray();
  const results = await Promise.allSettled(due.map((asset) => createScanRun(asset._id.toHexString(), asset.createdBy.toHexString())));
  return { queued: results.filter((result) => result.status === "fulfilled").length, failed: results.filter((result) => result.status === "rejected").length };
}

export async function failScan(scanRunId: string, error: unknown) {
  const { scanRuns } = await collections();
  await scanRuns.updateOne({ _id: new ObjectId(scanRunId) }, { $set: { status: "failed", completedAt: new Date(), error: error instanceof Error ? error.message.slice(0, 500) : "Scan failed" } });
}

export async function listScanRuns() {
  await failStaleScans();
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
