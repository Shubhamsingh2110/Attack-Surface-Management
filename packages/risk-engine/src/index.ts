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
function versionParts(value: string) { return value.split(".").map((part) => Number(part) || 0); }
function versionBelow(value: string, minimum: string) {
  const current = versionParts(value); const required = versionParts(minimum);
  for (let index = 0; index < Math.max(current.length, required.length); index += 1) {
    if ((current[index] ?? 0) !== (required[index] ?? 0)) return (current[index] ?? 0) < (required[index] ?? 0);
  }
  return false;
}

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
    if (["TLSv1", "TLSv1.1"].includes(String(tls.protocol))) candidates.push({ ruleId: "tls-obsolete-protocol", key: String(tls.protocol), title: "Obsolete TLS protocol negotiated", description: `The HTTPS endpoint negotiated ${String(tls.protocol)}, which is obsolete.`, remediation: "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer.", severity: "high", confidence: "high", exploitability: 0.7, evidence: { protocol: tls.protocol, cipher: tls.cipher } });
    if (typeof tls.keyBits === "number" && tls.keyBits < 2048) candidates.push({ ruleId: "tls-weak-public-key", key: String(tls.fingerprint256 ?? tls.keyBits), title: "TLS certificate uses a weak public key", description: `The presented certificate reports a ${tls.keyBits}-bit public key.`, remediation: "Replace the certificate and private key with a modern key meeting current organizational cryptographic requirements.", severity: "high", confidence: "high", exploitability: 0.7, evidence: { keyBits: tls.keyBits, fingerprint256: tls.fingerprint256 } });
  }
  const dns = byType.get("dns");
  if (dns) {
    const emailSecurity = object(dns.emailSecurity);
    const spf = Array.isArray(emailSecurity.spfRecords) ? emailSecurity.spfRecords.filter((value): value is string => typeof value === "string") : [];
    const dmarc = Array.isArray(emailSecurity.dmarcRecords) ? emailSecurity.dmarcRecords.filter((value): value is string => typeof value === "string") : [];
    const hasMail = Array.isArray(dns.mx) && dns.mx.length > 0;
    if (hasMail && spf.length === 0) candidates.push({ ruleId: "email-missing-spf", key: "spf", title: "SPF record is missing", description: "The domain receives email but does not publish an SPF policy.", remediation: "Publish one SPF TXT record that authorizes legitimate senders and ends with an appropriate all mechanism.", severity: "medium", confidence: "high", exploitability: 0.6, evidence: { mx: dns.mx } });
    if (spf.length > 1) candidates.push({ ruleId: "email-multiple-spf", key: "spf", title: "Multiple SPF records are published", description: "Publishing multiple SPF records causes SPF evaluation errors.", remediation: "Merge authorized senders into exactly one v=spf1 TXT record.", severity: "high", confidence: "high", exploitability: 0.7, evidence: { records: spf } });
    if (spf.some((record) => /(?:^|\s)\+all(?:\s|$)/i.test(record))) candidates.push({ ruleId: "email-spf-allow-all", key: spf.join("|"), title: "SPF policy authorizes every sender", description: "The SPF +all mechanism permits any server to send mail for this domain.", remediation: "Restrict SPF to approved senders and replace +all with a properly tested restrictive policy.", severity: "high", confidence: "high", exploitability: 0.9, evidence: { records: spf } });
    else if (spf.some((record) => /(?:^|\s)[?~]all(?:\s|$)/i.test(record))) candidates.push({ ruleId: "email-spf-weak-all", key: spf.join("|"), title: "SPF policy has a weak terminal mechanism", description: "The SPF policy ends with neutral or soft-fail handling, which provides limited spoofing resistance.", remediation: "Validate all legitimate senders, then move toward a hard-fail -all policy.", severity: "low", confidence: "high", exploitability: 0.5, evidence: { records: spf } });
    if (hasMail && dmarc.length === 0) candidates.push({ ruleId: "email-missing-dmarc", key: "dmarc", title: "DMARC record is missing", description: "The mail-enabled domain does not publish a DMARC policy.", remediation: "Publish a DMARC TXT record at _dmarc, begin with monitoring, review reports, and progress toward quarantine or reject.", severity: "medium", confidence: "high", exploitability: 0.6, evidence: { recordName: emailSecurity.dmarcRecordName } });
    if (dmarc.some((record) => /(?:^|;)\s*p=none(?:;|$)/i.test(record))) candidates.push({ ruleId: "email-dmarc-monitor-only", key: dmarc.join("|"), title: "DMARC policy is monitoring only", description: "DMARC p=none collects results but does not request quarantine or rejection of failing messages.", remediation: "Review DMARC reports and progressively enforce p=quarantine or p=reject.", severity: "low", confidence: "high", exploitability: 0.5, evidence: { records: dmarc } });
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
    const details = Array.isArray(http.technologyDetails) ? http.technologyDetails.map(object) : [];
    for (const detail of details) {
      const name = typeof detail.name === "string" ? detail.name.toLowerCase() : "";
      const version = typeof detail.version === "string" ? detail.version : "";
      const apacheOutdated = name === "apache" && version && versionBelow(version, "2.4.69");
      const phpOutdated = name === "php" && version && versionBelow(version, "8.2.0");
      const nginxOutdated = name === "nginx" && version && (versionBelow(version, "1.30.0") || (versionParts(version)[1] === 30 && versionBelow(version, "1.30.5")) || (versionParts(version)[1] === 31 && versionBelow(version, "1.31.6")));
      if (apacheOutdated || phpOutdated || nginxOutdated) candidates.push({ ruleId: "outdated-web-technology", key: `${name}:${version}`, title: `Potentially outdated ${detail.name} version exposed`, description: `The public response advertises ${detail.name} ${version}. The detected version is below the current conservative security baseline and may contain known vulnerabilities. Banner detection is not proof of the installed package version.`, remediation: "Confirm the installed version on the server, review the vendor security advisories, upgrade to a supported patched release, and suppress detailed version banners.", severity: "high", confidence: "medium", exploitability: 0.7, evidence: { technology: detail.name, version, source: detail.source, advisory: apacheOutdated ? "https://httpd.apache.org/security/vulnerabilities_24.html" : phpOutdated ? "https://www.php.net/supported-versions.php" : "https://nginx.org/en/security_advisories.html" } });
    }
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
