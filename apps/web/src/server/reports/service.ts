import "server-only";
import { ObjectId } from "mongodb";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import { getReportEnv } from "@asm/config";
import type { ReportFormat, ReportKind } from "@asm/contracts/reports";
import { collections, ensureIndexes } from "@asm/database";
import { deletePrivateReports, uploadPrivateReport } from "./cloudinary";

function csvCell(value: unknown) { return `"${String(value ?? "").replaceAll('"', '""')}"`; }

async function reportRows(kind: ReportKind) {
  const { assets, findings } = await collections();
  if (kind === "asset_inventory") {
    const rows = await assets.find().sort({ criticality: 1, value: 1 }).toArray();
    return { title: "Asset Inventory", headings: ["Asset", "Type", "Criticality", "Ownership", "Last scan"], rows: rows.map((row) => [row.value, row.type, row.criticality, row.ownershipStatus, row.lastScanAt?.toISOString() ?? "Never"]) };
  }
  const rows = await findings.find(kind === "executive" ? { status: { $in: ["open", "investigating"] } } : {}).sort({ riskScore: -1 }).limit(2_000).toArray();
  if (kind === "executive") {
    const counts = rows.reduce<Record<string, number>>((all, row) => ({ ...all, [row.severity]: (all[row.severity] ?? 0) + 1 }), {});
    return { title: "Executive Exposure Summary", headings: ["Metric", "Value"], rows: [["Open findings", rows.length], ["Critical", counts.critical ?? 0], ["High", counts.high ?? 0], ["Medium", counts.medium ?? 0], ["Average risk", rows.length ? Math.round(rows.reduce((sum, row) => sum + row.riskScore, 0) / rows.length) : 0]] };
  }
  return { title: "Technical Findings", headings: ["Severity", "Title", "Status", "Risk", "First seen", "Remediation"], rows: rows.map((row) => [row.severity, row.title, row.status, row.riskScore, row.firstSeenAt.toISOString(), row.remediation]) };
}

async function toPdf(title: string, headings: string[], rows: unknown[][]) {
  const document = await PDFDocument.create();
  const font = await document.embedFont(StandardFonts.Helvetica);
  const bold = await document.embedFont(StandardFonts.HelveticaBold);
  let page = document.addPage([595, 842]);
  let y = 800;
  const line = (value: string, strong = false) => {
    if (y < 45) { page = document.addPage([595, 842]); y = 800; }
    page.drawText(value.slice(0, 105), { x: 40, y, size: strong ? 13 : 8, font: strong ? bold : font, color: strong ? rgb(0.08, 0.25, 0.2) : rgb(0.12, 0.15, 0.2) });
    y -= strong ? 24 : 14;
  };
  line(title, true); line(`Generated ${new Date().toISOString()}`); y -= 8; line(headings.join(" | "), true);
  for (const row of rows) line(row.map((value) => String(value ?? "").replaceAll(/\s+/g, " ")).join(" | "));
  return Buffer.from(await document.save());
}

export async function createReport(kind: ReportKind, format: ReportFormat, adminId: string) {
  await ensureIndexes();
  const { REPORT_RETENTION_DAYS } = getReportEnv();
  const { reports } = await collections();
  const now = new Date();
  const result = await reports.insertOne({ kind, format, status: "generating", createdBy: new ObjectId(adminId), createdAt: now, expiresAt: new Date(now.getTime() + REPORT_RETENTION_DAYS * 86_400_000) });
  try {
    const data = await reportRows(kind);
    const buffer = format === "csv" ? Buffer.from([data.headings, ...data.rows].map((row) => row.map(csvCell).join(",")).join("\n"), "utf8") : await toPdf(data.title, data.headings, data.rows);
    const publicId = `asm/reports/${result.insertedId.toHexString()}`;
    const uploaded = await uploadPrivateReport(publicId, buffer);
    await reports.updateOne({ _id: result.insertedId }, { $set: { status: "ready", cloudinaryPublicId: uploaded.publicId, bytes: uploaded.bytes } });
  } catch (error) {
    await reports.updateOne({ _id: result.insertedId }, { $set: { status: "failed", error: error instanceof Error ? error.message.slice(0, 500) : "Report generation failed." } });
    throw error;
  }
}

export async function listReports() {
  const { reports } = await collections();
  return reports.find().sort({ createdAt: -1 }).limit(100).toArray();
}

export async function cleanupExpiredReports() {
  const { reports } = await collections();
  const expired = await reports.find({ expiresAt: { $lte: new Date() } }).limit(100).toArray();
  await deletePrivateReports(expired.flatMap((row) => row.cloudinaryPublicId ? [row.cloudinaryPublicId] : []));
  if (expired.length) await reports.deleteMany({ _id: { $in: expired.map((row) => row._id) } });
  return expired.length;
}
