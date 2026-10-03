import { NextResponse, type NextRequest } from "next/server";
import { ObjectId } from "mongodb";
import { collections } from "@asm/database";
import { getCurrentAdmin } from "@/server/auth/session";
import { signedReportUrl } from "@/server/reports/cloudinary";

export async function GET(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = await getCurrentAdmin();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  if (!ObjectId.isValid(id)) return NextResponse.json({ error: "Not found" }, { status: 404 });
  const { reports } = await collections();
  const report = await reports.findOne({ _id: new ObjectId(id), status: "ready", expiresAt: { $gt: new Date() } });
  if (!report?.cloudinaryPublicId) return NextResponse.json({ error: "Report unavailable" }, { status: 404 });
  return NextResponse.redirect(signedReportUrl(report.cloudinaryPublicId, report.format));
}
