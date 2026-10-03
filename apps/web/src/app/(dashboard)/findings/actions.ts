"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { addFindingCommentSchema, bulkFindingUpdateSchema, updateFindingSchema } from "@asm/contracts/findings";
import { getCurrentAdmin } from "@/server/auth/session";
import { addFindingComment, bulkUpdateFindings, updateFinding } from "@/server/findings/service";

function done(path: string, message: string, error = false): never { redirect(`${path}?${error ? "error" : "message"}=${encodeURIComponent(message)}`); }

export async function updateFindingAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("/findings", "Unauthorized", true);
  const parsed = updateFindingSchema.safeParse({ findingId: formData.get("findingId"), status: formData.get("status"), acceptedUntil: formData.get("acceptedUntil") || undefined, comment: formData.get("comment") || undefined });
  if (!parsed.success) done(`/findings/${formData.get("findingId")}`, parsed.error.issues[0]?.message ?? "Invalid update", true);
  try { await updateFinding({ ...parsed.data, actorId: admin.id }); revalidatePath("/findings"); revalidatePath(`/findings/${parsed.data.findingId}`); }
  catch (error) { done(`/findings/${parsed.data.findingId}`, error instanceof Error ? error.message : "Update failed", true); }
  done(`/findings/${parsed.data.findingId}`, "Finding updated.");
}

export async function addCommentAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("/findings", "Unauthorized", true);
  const parsed = addFindingCommentSchema.safeParse({ findingId: formData.get("findingId"), comment: formData.get("comment") });
  if (!parsed.success) done(`/findings/${formData.get("findingId")}`, "Enter a comment.", true);
  await addFindingComment(parsed.data.findingId, parsed.data.comment, admin.id);
  revalidatePath(`/findings/${parsed.data.findingId}`);
  done(`/findings/${parsed.data.findingId}`, "Comment added.");
}

export async function bulkFindingAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("/findings", "Unauthorized", true);
  const parsed = bulkFindingUpdateSchema.safeParse({ findingIds: formData.getAll("findingIds"), status: formData.get("status") });
  if (!parsed.success) done("/findings", "Select at least one finding and a valid status.", true);
  await bulkUpdateFindings(parsed.data.findingIds, parsed.data.status, admin.id);
  revalidatePath("/findings");
  done("/findings", `${parsed.data.findingIds.length} finding(s) updated.`);
}
