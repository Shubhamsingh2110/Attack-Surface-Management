import type { AssetCriticality } from "@asm/contracts/assets";
import type { FindingConfidence, FindingSeverity } from "@asm/contracts/findings";

export interface CandidateFinding {
  ruleId: string;
  key: string;
  title: string;
  description: string;
  remediation: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  exploitability: number;
  evidence: Record<string, unknown>;
}

const severityScore: Record<FindingSeverity, number> = { critical: 95, high: 75, medium: 50, low: 25, info: 5 };
const confidenceScore: Record<FindingConfidence, number> = { high: 1, medium: 0.8, low: 0.6 };
const criticalityScore: Record<AssetCriticality, number> = { low: 0.75, medium: 1, high: 1.15, critical: 1.3 };

export function calculateRisk(severity: FindingSeverity, confidence: FindingConfidence, criticality: AssetCriticality, exploitability: number) {
  const factors = { severity: severityScore[severity], confidence: confidenceScore[confidence], exposure: 1, criticality: criticalityScore[criticality], exploitability };
  return { riskScore: Math.min(100, Math.round(factors.severity * factors.confidence * factors.exposure * factors.criticality * factors.exploitability)), riskFactors: factors };
}

function object(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }

export function detectFindings(input: { assetValue: string; observations: Array<{ type: string; data: Record<string, unknown> }>; knownAssets: string[] }) {
  const candidates: CandidateFinding[] = [];
  const byType = new Map(input.observations.map((item) => [item.type, item.data]));
  const tls = byType.get("tls");
  if (tls) {
    if (tls.authorized === false) candidates.push({ ruleId: "tls-untrusted", key: "certificate", title: "TLS certificate is not trusted", description: "The public TLS endpoint presented a certificate that could not be validated.", remediation: "Install a valid certificate with a complete trusted chain and matching hostname.", severity: "high", confidence: "high", exploitability: 0.8, evidence: tls });
    const validTo = typeof tls.validTo === "string" ? new Date(tls.validTo) : null;
    if (validTo && !Number.isNaN(validTo.getTime())) {
      const days = Math.ceil((validTo.getTime() - Date.now()) / 86_400_000);
      if (days < 0) candidates.push({ ruleId: "tls-expired", key: "certificate", title: "TLS certificate has expired", description: `The certificate expired ${Math.abs(days)} day(s) ago.`, remediation: "Renew and deploy the certificate immediately.", severity: "critical", confidence: "high", exploitability: 0.9, evidence: { validTo: tls.validTo, daysRemaining: days } });
      else if (days <= 30) candidates.push({ ruleId: "tls-expiring", key: "certificate", title: "TLS certificate expires soon", description: `The certificate expires in ${days} day(s).`, remediation: "Renew the certificate before its expiration date.", severity: days <= 7 ? "high" : "medium", confidence: "high", exploitability: 0.6, evidence: { validTo: tls.validTo, daysRemaining: days } });
    }
  }
  const http = byType.get("http");
  if (http) {
    const headers = object(http.securityHeaders);
    const rules = [
      ["strictTransportSecurity", "missing-hsts", "HTTP Strict Transport Security is missing", "Enable HSTS with an appropriate max-age and includeSubDomains after validation.", "high"],
      ["contentSecurityPolicy", "missing-csp", "Content Security Policy is missing", "Deploy a restrictive, nonce-based Content Security Policy.", "medium"],
      ["xContentTypeOptions", "missing-nosniff", "MIME-sniffing protection is missing", "Set X-Content-Type-Options to nosniff.", "low"],
      ["xFrameOptions", "missing-frame-protection", "Frame embedding protection is missing", "Use CSP frame-ancestors and X-Frame-Options where legacy coverage is required.", "medium"],
      ["referrerPolicy", "missing-referrer-policy", "Referrer Policy is missing", "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin.", "low"],
      ["permissionsPolicy", "missing-permissions-policy", "Permissions Policy is missing", "Disable browser capabilities that the application does not require.", "low"],
    ] as const;
    for (const [field, ruleId, title, remediation, severity] of rules) if (!headers[field]) candidates.push({ ruleId, key: field, title, description: `${title} on the public HTTPS response.`, remediation, severity, confidence: "high", exploitability: severity === "high" ? 0.7 : 0.5, evidence: { header: field, observed: null } });
    const technologies = Array.isArray(http.technologies) ? http.technologies.filter((item): item is string => typeof item === "string") : [];
    if (technologies.length) candidates.push({ ruleId: "technology-disclosure", key: technologies.join("|"), title: "Server technology is disclosed", description: "Response headers reveal server or framework technology.", remediation: "Remove unnecessary Server and X-Powered-By response headers.", severity: "low", confidence: "high", exploitability: 0.4, evidence: { technologies } });
    if (typeof http.status === "number" && http.status >= 500) candidates.push({ ruleId: "http-server-error", key: String(http.status), title: "Public endpoint returns a server error", description: `The endpoint returned HTTP ${http.status}.`, remediation: "Review application availability and upstream service health.", severity: "medium", confidence: "high", exploitability: 0.5, evidence: { status: http.status } });
  }
  const certificates = byType.get("certificates");
  if (certificates && Array.isArray(certificates.names)) {
    const known = new Set(input.knownAssets);
    const unmanaged = certificates.names.filter((name): name is string => typeof name === "string" && name !== input.assetValue && !known.has(name)).slice(0, 100);
    if (unmanaged.length) candidates.push({ ruleId: "unmanaged-subdomains", key: unmanaged.sort().join("|"), title: "Potential unmanaged subdomains discovered", description: `${unmanaged.length} certificate-backed hostname(s) are not present in the asset inventory.`, remediation: "Review the discovered hostnames, assign ownership, and add approved assets to inventory.", severity: "medium", confidence: "medium", exploitability: 0.5, evidence: { hostnames: unmanaged } });
  }
  return candidates;
}

export function slaDays(severity: FindingSeverity) { return ({ critical: 2, high: 7, medium: 30, low: 90, info: 180 } as const)[severity]; }
