import { z } from "zod";

const runtimeSchema = z.object({
  MONGODB_URI: z.string().min(1),
  MONGODB_DB: z.string().min(1).default("attack_surface_management"),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(720).default(24),
});

export function getRuntimeEnv() {
  const result = runtimeSchema.safeParse(process.env);
  if (!result.success) throw new Error(`Invalid server environment: ${result.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
  return result.data;
}

const reportEnvSchema = z.object({
  CLOUDINARY_URL: z.string().min(1),
  REPORT_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(30),
});

export function getReportEnv() {
  const result = reportEnvSchema.safeParse(process.env);
  if (!result.success) throw new Error(`Invalid report environment: ${result.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
  return result.data;
}

export function getIntegrationEncryptionKey() {
  const result = z.string().min(1).safeParse(process.env.INTEGRATION_ENCRYPTION_KEY);
  if (!result.success) throw new Error("INTEGRATION_ENCRYPTION_KEY is not configured.");
  return result.data;
}

const adminSchema = z.object({
  ADMIN_EMAIL: z.email().transform((value) => value.toLowerCase()),
  ADMIN_PASSWORD: z.string().min(14).max(128),
  ADMIN_NAME: z.string().trim().min(2).max(80).default("Administrator"),
});

export function getAdminEnv() {
  const result = adminSchema.safeParse(process.env);
  if (!result.success) throw new Error(`Invalid admin environment: ${result.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
  return result.data;
}
