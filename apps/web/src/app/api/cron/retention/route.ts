import { cleanupExpiredReports } from "@/server/reports/service";

export async function GET(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || request.headers.get("authorization") !== `Bearer ${secret}`) return new Response("Unauthorized", { status: 401 });
  try {
    const removed = await cleanupExpiredReports();
    console.info(JSON.stringify({ level: "info", event: "report_retention_complete", removed }));
    return Response.json({ removed }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    console.error(JSON.stringify({ level: "error", event: "report_retention_failed", error: error instanceof Error ? error.message : "unknown" }));
    return Response.json({ error: "Retention cleanup failed" }, { status: 500 });
  }
}
