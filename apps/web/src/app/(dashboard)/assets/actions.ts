"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { createAssetSchema, createChallengeSchema, assetIdSchema, authorizePassiveScanSchema } from "@asm/contracts/assets";
import { writeAuditLog } from "@/server/audit/log";
import { getCurrentAdmin } from "@/server/auth/session";
import { attestPassiveScanAuthorization, createAsset, createOwnershipChallenge, verifyAssetOwnership } from "@/server/assets/service";
import { createScanRun } from "@/server/scans/service";

function done(message: string, error = false): never {
  redirect(`/assets?${error ? "error" : "message"}=${encodeURIComponent(message)}`);
}

export async function addAssetAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("Unauthorized", true);
  const parsed = createAssetSchema.safeParse({
    type: formData.get("type"), value: formData.get("value"), displayName: formData.get("displayName") || undefined,
    criticality: formData.get("criticality"), scanFrequency: formData.get("scanFrequency"), tags: String(formData.get("tags") ?? "").split(",").map((tag) => tag.trim()).filter(Boolean),
  });
  if (!parsed.success) done(parsed.error.issues[0]?.message ?? "Invalid asset", true);
  try { await createAsset({ ...parsed.data, adminId: admin.id }); revalidatePath("/assets"); }
  catch (error) { done(error instanceof Error && error.message.includes("duplicate") ? "That asset already exists." : error instanceof Error ? error.message : "Unable to add asset.", true); }
  done("Asset added. Verify ownership before scanning.");
}

export async function createChallengeAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("Unauthorized", true);
  const parsed = createChallengeSchema.safeParse({ assetId: formData.get("assetId"), method: formData.get("method") });
  if (!parsed.success) done("Invalid verification request.", true);
  try { await createOwnershipChallenge(parsed.data.assetId, parsed.data.method); revalidatePath("/assets"); }
  catch (error) { done(error instanceof Error ? error.message : "Unable to create challenge.", true); }
  done("Verification challenge created.");
}

export async function verifyAssetAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("Unauthorized", true);
  const parsed = assetIdSchema.safeParse(formData.get("assetId"));
  if (!parsed.success) done("Invalid asset.", true);
  try { await verifyAssetOwnership(parsed.data); revalidatePath("/assets"); }
  catch (error) { done(error instanceof Error ? error.message : "Verification failed.", true); }
  done("Asset ownership verified.");
}

export async function authorizePassiveScanAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("Unauthorized", true);
  const parsed = authorizePassiveScanSchema.safeParse({ assetId: formData.get("assetId"), authorizationBasis: formData.get("authorizationBasis"), confirmed: formData.get("confirmed") });
  if (!parsed.success) done(parsed.error.issues[0]?.message ?? "Authorization confirmation is required.", true);
  try {
    const result = await attestPassiveScanAuthorization(parsed.data.assetId, parsed.data.authorizationBasis, admin.id);
    await writeAuditLog({ event: "asset.passive_scan_authorized", actorId: result.actorId, outcome: "success", metadata: { asset: result.asset, authorizationBasis: parsed.data.authorizationBasis } });
    revalidatePath("/assets");
  } catch (error) { done(error instanceof Error ? error.message : "Unable to authorize passive scanning.", true); }
  done("Passive assessment authorization recorded. You can now scan this asset.");
}

export async function startScanAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("Unauthorized", true);
  const parsed = assetIdSchema.safeParse(formData.get("assetId"));
  if (!parsed.success) done("Invalid asset.", true);
  try { await createScanRun(parsed.data, admin.id); revalidatePath("/scans"); }
  catch (error) { done(error instanceof Error ? error.message : "Unable to start scan.", true); }
  redirect("/scans?message=Scan queued successfully.");
}
