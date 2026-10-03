"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { writeAuditLog } from "@/server/audit/log";
import { loginSchema } from "@asm/contracts/auth";
import { LOCKOUT_MINUTES, MAX_LOGIN_ATTEMPTS } from "@asm/security/constants";
import { verifyPassword } from "@asm/security/password";
import { createSession, deleteCurrentSession } from "@/server/auth/session";
import { collections } from "@asm/database";

export type LoginState = { error?: string } | undefined;

export async function loginAction(_: LoginState, formData: FormData): Promise<LoginState> {
  const parsed = loginSchema.safeParse({ email: formData.get("email"), password: formData.get("password") });
  if (!parsed.success) return { error: "Enter a valid email and password." };

  const { admins } = await collections();
  const admin = await admins.findOne({ email: parsed.data.email });
  const now = new Date();

  if (!admin || !admin.isActive || (admin.lockedUntil && admin.lockedUntil > now)) {
    await writeAuditLog({ event: "auth.login", actorId: admin?._id, outcome: "failure", metadata: { reason: admin?.lockedUntil ? "locked" : "invalid" } });
    return { error: "Invalid credentials or account temporarily locked." };
  }

  const valid = await verifyPassword(admin.passwordHash, parsed.data.password);
  if (!valid) {
    const attempts = admin.failedLoginAttempts + 1;
    const update: { failedLoginAttempts: number; updatedAt: Date; lockedUntil?: Date } = { failedLoginAttempts: attempts, updatedAt: now };
    if (attempts >= MAX_LOGIN_ATTEMPTS) update.lockedUntil = new Date(now.getTime() + LOCKOUT_MINUTES * 60_000);
    await admins.updateOne({ _id: admin._id }, { $set: update });
    await writeAuditLog({ event: "auth.login", actorId: admin._id, outcome: "failure", metadata: { reason: "invalid_password" } });
    return { error: "Invalid credentials or account temporarily locked." };
  }

  await admins.updateOne({ _id: admin._id }, { $set: { failedLoginAttempts: 0, lastLoginAt: now, updatedAt: now }, $unset: { lockedUntil: "" } });
  const userAgent = (await headers()).get("user-agent")?.slice(0, 300);
  await createSession(admin._id, userAgent);
  await writeAuditLog({ event: "auth.login", actorId: admin._id, outcome: "success" });
  redirect("/dashboard");
}

export async function logoutAction() {
  await deleteCurrentSession();
  redirect("/login");
}
