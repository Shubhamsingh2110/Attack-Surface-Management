import "server-only";
import { collections, ensureIndexes } from "@asm/database";

export async function enforceRateLimit(key: string, limit: number, windowSeconds: number) {
  await ensureIndexes();
  const { rateLimits } = await collections();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + windowSeconds * 1_000);
  const result = await rateLimits.findOneAndUpdate(
    { key, expiresAt: { $gt: now } },
    { $inc: { count: 1 } },
    { returnDocument: "after" },
  );
  if (result) {
    if (result.count > limit) throw new Error("Too many requests. Try again later.");
    return;
  }
  try { await rateLimits.insertOne({ key, count: 1, expiresAt }); }
  catch {
    const retry = await rateLimits.findOneAndUpdate({ key }, { $inc: { count: 1 } }, { returnDocument: "after" });
    if (retry && retry.count > limit) throw new Error("Too many requests. Try again later.");
  }
}
