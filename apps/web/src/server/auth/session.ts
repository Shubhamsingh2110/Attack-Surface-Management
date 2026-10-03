import "server-only";
import { createHash, randomBytes } from "node:crypto";
import type { ObjectId } from "mongodb";
import { cookies } from "next/headers";
import { cache } from "react";
import { getRuntimeEnv } from "@asm/config";
import { collections } from "@asm/database";
import { SESSION_COOKIE } from "@asm/security/constants";

function digest(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export async function createSession(adminId: ObjectId, userAgent?: string) {
  const token = randomBytes(32).toString("base64url");
  const now = new Date();
  const { SESSION_TTL_HOURS } = getRuntimeEnv();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_HOURS * 60 * 60 * 1_000);
  const { sessions } = await collections();

  await sessions.insertOne({ adminId, tokenHash: digest(token), createdAt: now, expiresAt, userAgent });
  (await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
    priority: "high",
  });
}

export const getCurrentAdmin = cache(async () => {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) return null;

  const { sessions, admins } = await collections();
  const session = await sessions.findOne({ tokenHash: digest(token), expiresAt: { $gt: new Date() } });
  if (!session) return null;

  const admin = await admins.findOne({ _id: session.adminId, isActive: true });
  if (!admin || admin.passwordChangedAt > session.createdAt) return null;
  return { id: admin._id.toHexString(), email: admin.email, name: admin.name, role: admin.role };
});

export async function deleteCurrentSession() {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE)?.value;
  if (token) {
    const { sessions } = await collections();
    await sessions.deleteOne({ tokenHash: digest(token) });
  }
  cookieStore.delete(SESSION_COOKIE);
}
