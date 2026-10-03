import { z } from "zod";

export const integrationTypeSchema = z.enum(["slack", "teams", "webhook", "siem", "jira", "servicenow"]);
export const createIntegrationSchema = z.object({
  name: z.string().trim().min(2).max(80),
  type: integrationTypeSchema,
  endpoint: z.url().refine((value) => new URL(value).protocol === "https:", "Only HTTPS endpoints are allowed."),
  username: z.string().trim().max(200).optional(),
  secret: z.string().max(2_000).optional(),
  projectKey: z.string().trim().max(40).optional(),
});
export const integrationIdSchema = z.string().regex(/^[a-f\d]{24}$/i);
export type IntegrationType = z.infer<typeof integrationTypeSchema>;
