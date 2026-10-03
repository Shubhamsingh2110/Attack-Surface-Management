import "server-only";
import { createHmac } from "node:crypto";
import { ObjectId } from "mongodb";
import { getIntegrationEncryptionKey } from "@asm/config";
import type { IntegrationType } from "@asm/contracts/integrations";
import { collections, ensureIndexes } from "@asm/database";
import { decryptSecret, encryptSecret } from "@asm/security/encryption";
import { postJsonToPublicUrl } from "@asm/scanner-core";

interface IntegrationConfig { endpoint: string; username?: string; secret?: string; projectKey?: string }

export async function createIntegration(input: IntegrationConfig & { name: string; type: IntegrationType; adminId: string }) {
  await ensureIndexes();
  const { integrations } = await collections();
  const { name, type, adminId, ...config } = input;
  const now = new Date();
  await integrations.insertOne({ name, type, encryptedConfig: encryptSecret(JSON.stringify(config), getIntegrationEncryptionKey()), enabled: true, createdBy: new ObjectId(adminId), createdAt: now, updatedAt: now });
}

export async function listIntegrations() {
  const { integrations, deliveries } = await collections();
  const rows = await integrations.find().sort({ createdAt: -1 }).toArray();
  return Promise.all(rows.map(async (row) => ({ ...row, latestDelivery: await deliveries.findOne({ integrationId: row._id }, { sort: { createdAt: -1 } }) })));
}

function deliveryRequest(type: IntegrationType, config: IntegrationConfig, payload: Record<string, unknown>): { endpoint: string; body: Record<string, unknown>; headers: Record<string, string> } {
  const text = String(payload.message ?? "ASM notification");
  if (type === "slack") return { endpoint: config.endpoint, body: { text }, headers: {} };
  if (type === "teams") return { endpoint: config.endpoint, body: { type: "message", attachments: [{ contentType: "application/vnd.microsoft.card.adaptive", content: { type: "AdaptiveCard", version: "1.4", body: [{ type: "TextBlock", text, wrap: true }] } }] }, headers: {} };
  if (type === "jira") return { endpoint: `${config.endpoint.replace(/\/$/, "")}/rest/api/3/issue`, body: { fields: { project: { key: config.projectKey }, summary: text.slice(0, 240), description: { type: "doc", version: 1, content: [{ type: "paragraph", content: [{ type: "text", text }] }] }, issuetype: { name: "Task" } } }, headers: { Authorization: `Basic ${Buffer.from(`${config.username}:${config.secret}`).toString("base64")}` } };
  if (type === "servicenow") return { endpoint: `${config.endpoint.replace(/\/$/, "")}/api/now/table/incident`, body: { short_description: text.slice(0, 160), description: text }, headers: { Authorization: `Basic ${Buffer.from(`${config.username}:${config.secret}`).toString("base64")}` } };
  const body = { event: payload.event ?? "asm.notification", createdAt: new Date().toISOString(), data: payload };
  const raw = JSON.stringify(body);
  const headers: Record<string, string> = config.secret ? { "X-ASM-Signature": `sha256=${createHmac("sha256", config.secret).update(raw).digest("hex")}` } : {};
  return { endpoint: config.endpoint, body, headers };
}

async function deliver(integrationId: ObjectId, event: "test" | "finding.created", payload: Record<string, unknown>) {
  const { integrations, deliveries } = await collections();
  const integration = await integrations.findOne({ _id: integrationId, enabled: true });
  if (!integration) throw new Error("Integration not found or disabled.");
  const delivery = await deliveries.insertOne({ integrationId, event, status: "pending", attemptCount: 0, createdAt: new Date() });
  let lastError = "Delivery failed.";
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const config = JSON.parse(decryptSecret(integration.encryptedConfig, getIntegrationEncryptionKey())) as IntegrationConfig;
      const request = deliveryRequest(integration.type, config, payload);
      const response = await postJsonToPublicUrl(request.endpoint, request.body, request.headers);
      if (response.status < 200 || response.status >= 300) throw new Error(`Endpoint returned HTTP ${response.status}.`);
      await deliveries.updateOne({ _id: delivery.insertedId }, { $set: { status: "delivered", attemptCount: attempt, responseStatus: response.status, deliveredAt: new Date() }, $unset: { error: "" } });
      return;
    } catch (error) { lastError = error instanceof Error ? error.message : "Delivery failed."; }
  }
  await deliveries.updateOne({ _id: delivery.insertedId }, { $set: { status: "failed", attemptCount: 3, error: lastError.slice(0, 500) } });
  throw new Error(lastError);
}

export async function testIntegration(id: string) { await deliver(new ObjectId(id), "test", { event: "test", message: "ASM Control integration test succeeded." }); }

export async function notifyNewFinding(input: { title: string; severity: string; riskScore: number; asset: string }) {
  const { integrations } = await collections();
  const enabled = await integrations.find({ enabled: true }).toArray();
  await Promise.allSettled(enabled.map((row) => deliver(row._id, "finding.created", { event: "finding.created", message: `[${input.severity.toUpperCase()}] ${input.title} on ${input.asset} (risk ${input.riskScore})`, ...input })));
}

export async function deleteIntegration(id: string) {
  const { integrations } = await collections();
  await integrations.deleteOne({ _id: new ObjectId(id) });
}
