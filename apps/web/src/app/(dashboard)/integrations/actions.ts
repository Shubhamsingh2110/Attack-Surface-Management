"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { createIntegrationSchema, integrationIdSchema } from "@asm/contracts/integrations";
import { getCurrentAdmin } from "@/server/auth/session";
import { createIntegration, deleteIntegration, testIntegration } from "@/server/integrations/service";
import { enforceRateLimit } from "@/server/rate-limit";

function done(message: string, error = false): never { redirect(`/integrations?${error ? "error" : "message"}=${encodeURIComponent(message)}`); }

export async function createIntegrationAction(formData: FormData) {
  const admin = await getCurrentAdmin(); if (!admin) done("Unauthorized", true);
  const parsed = createIntegrationSchema.safeParse({ name: formData.get("name"), type: formData.get("type"), endpoint: formData.get("endpoint"), username: formData.get("username") || undefined, secret: formData.get("secret") || undefined, projectKey: formData.get("projectKey") || undefined });
  if (!parsed.success) done(parsed.error.issues[0]?.message ?? "Invalid integration.", true);
  try { await enforceRateLimit(`integration:${admin.id}`, 20, 3_600); await createIntegration({ ...parsed.data, adminId: admin.id }); revalidatePath("/integrations"); }
  catch (error) { done(error instanceof Error ? error.message : "Unable to save integration.", true); }
  done("Integration saved with encrypted credentials.");
}

export async function testIntegrationAction(formData: FormData) {
  const admin = await getCurrentAdmin(); if (!admin) done("Unauthorized", true);
  const parsed = integrationIdSchema.safeParse(formData.get("integrationId")); if (!parsed.success) done("Invalid integration.", true);
  try { await enforceRateLimit(`integration-test:${admin.id}`, 10, 600); await testIntegration(parsed.data); revalidatePath("/integrations"); }
  catch (error) { done(error instanceof Error ? error.message : "Test failed.", true); }
  done("Test notification delivered.");
}

export async function deleteIntegrationAction(formData: FormData) {
  const admin = await getCurrentAdmin(); if (!admin) done("Unauthorized", true);
  const parsed = integrationIdSchema.safeParse(formData.get("integrationId")); if (!parsed.success) done("Invalid integration.", true);
  await deleteIntegration(parsed.data); revalidatePath("/integrations"); done("Integration removed.");
}
