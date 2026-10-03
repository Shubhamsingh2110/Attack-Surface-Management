import { loadEnvFile } from "node:process";
import { getAdminEnv } from "@asm/config";
import { strongPasswordSchema } from "@asm/contracts/auth";
import { collections, ensureIndexes } from "@asm/database";
import { hashPassword } from "@asm/security/password";

try { loadEnvFile(".env.local"); } catch { loadEnvFile(".env"); }

async function main() {
  const env = getAdminEnv();
  strongPasswordSchema.parse(env.ADMIN_PASSWORD);
  await ensureIndexes();
  const { admins } = await collections();
  const existingCount = await admins.countDocuments();
  if (existingCount > 0) throw new Error("An admin already exists. Use npm run admin:reset-password instead.");
  const now = new Date();
  await admins.insertOne({
    email: env.ADMIN_EMAIL,
    name: env.ADMIN_NAME,
    passwordHash: await hashPassword(env.ADMIN_PASSWORD),
    role: "admin",
    isActive: true,
    failedLoginAttempts: 0,
    passwordChangedAt: now,
    createdAt: now,
    updatedAt: now,
  });
  console.log(`Admin created for ${env.ADMIN_EMAIL}. Remove ADMIN_PASSWORD from the environment now.`);
}

main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exitCode = 1; });
