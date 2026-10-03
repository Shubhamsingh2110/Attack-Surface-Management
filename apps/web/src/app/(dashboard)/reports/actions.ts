"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { createReportSchema } from "@asm/contracts/reports";
import { getCurrentAdmin } from "@/server/auth/session";
import { enforceRateLimit } from "@/server/rate-limit";
import { createReport } from "@/server/reports/service";

function done(message: string, error = false): never { redirect(`/reports?${error ? "error" : "message"}=${encodeURIComponent(message)}`); }

export async function createReportAction(formData: FormData) {
  const admin = await getCurrentAdmin();
  if (!admin) done("Unauthorized", true);
  const parsed = createReportSchema.safeParse({ kind: formData.get("kind"), format: formData.get("format") });
  if (!parsed.success) done("Choose a valid report type and format.", true);
  try {
    await enforceRateLimit(`report:${admin.id}`, 10, 3_600);
    await createReport(parsed.data.kind, parsed.data.format, admin.id);
    revalidatePath("/reports");
  } catch (error) { done(error instanceof Error ? error.message : "Report generation failed.", true); }
  done("Report generated and stored privately.");
}
