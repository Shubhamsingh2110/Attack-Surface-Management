import { getDatabase } from "@asm/database";

export async function GET() {
  try {
    await (await getDatabase()).command({ ping: 1 });
    return Response.json({ status: "ok", database: "connected" }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ status: "degraded", database: "unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
