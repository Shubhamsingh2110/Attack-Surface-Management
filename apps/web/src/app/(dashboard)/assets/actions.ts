"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { createAssetSchema, createChallengeSchema, assetIdSchema } from "@asm/contracts/assets";
import { getCurrentAdmin } from "@/server/auth/session";
import { createAsset, createOwnershipChallenge, verifyAssetOwnership } from "@/server/assets/service";
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

export async function startScanAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("Unauthorized", true);
  const parsed = assetIdSchema.safeParse(formData.get("assetId"));
  if (!parsed.success) done("Invalid asset.", true);
  try { await createScanRun(parsed.data, admin.id); revalidatePath("/scans"); }
  catch (error) { done(error instanceof Error ? error.message : "Unable to start scan.", true); }
  redirect("/scans?message=Scan queued successfully.");
}
