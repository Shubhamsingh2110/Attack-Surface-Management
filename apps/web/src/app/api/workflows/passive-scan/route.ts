import { serve } from "@upstash/workflow/nextjs";
import { scanWorkflowPayloadSchema, type ScanWorkflowPayload } from "@asm/contracts/scans";
import { completeScan, failScan, scanStep, startScan } from "@/server/scans/service";

export const maxDuration = 60;

export const { POST } = serve<ScanWorkflowPayload>(async (context) => {
  const payload = scanWorkflowPayloadSchema.parse(context.requestPayload);
  try {
    await context.run("mark-scan-running", () => startScan(payload.scanRunId));
    await context.run("discover-dns", () => scanStep(payload.scanRunId, payload.assetId, "dns"));
    await context.run("discover-certificates", () => scanStep(payload.scanRunId, payload.assetId, "certificates"));
    await context.run("query-rdap", () => scanStep(payload.scanRunId, payload.assetId, "rdap"));
    await context.run("inspect-tls", () => scanStep(payload.scanRunId, payload.assetId, "tls"));
    await context.run("inspect-http", () => scanStep(payload.scanRunId, payload.assetId, "http"));
    await context.run("complete-scan", () => completeScan(payload.scanRunId, payload.assetId));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Passive scan failed";
    await context.run("record-scan-failure", () => failScan(payload.scanRunId, message));
    throw error;
  }
});
