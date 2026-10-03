import { loadEnvFile } from "node:process";
import { getAdminEnv } from "@asm/config";
import { strongPasswordSchema } from "@asm/contracts/auth";
import { collections } from "@asm/database";
import { hashPassword } from "@asm/security/password";

try { loadEnvFile(".env.local"); } catch { loadEnvFile(".env"); }

async function main() {
  const env = getAdminEnv();
  strongPasswordSchema.parse(env.ADMIN_PASSWORD);
  const { admins, sessions } = await collections();
  const admin = await admins.findOne({ email: env.ADMIN_EMAIL });
  if (!admin) throw new Error("No admin exists for ADMIN_EMAIL. Run npm run admin:seed first.");
  const now = new Date();
  await admins.updateOne({ _id: admin._id }, { $set: { passwordHash: await hashPassword(env.ADMIN_PASSWORD), passwordChangedAt: now, updatedAt: now, failedLoginAttempts: 0 }, $unset: { lockedUntil: "" } });
  await sessions.deleteMany({ adminId: admin._id });
  console.log(`Password reset for ${env.ADMIN_EMAIL}; all sessions were revoked. Remove ADMIN_PASSWORD from the environment now.`);
}

main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exitCode = 1; });
