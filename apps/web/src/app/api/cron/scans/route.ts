import { queueDueScans } from "@/server/scans/service";

export async function GET(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || request.headers.get("authorization") !== `Bearer ${secret}`) return new Response("Unauthorized", { status: 401 });
  return Response.json(await queueDueScans(), { headers: { "Cache-Control": "no-store" } });
}
