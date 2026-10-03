import { describe, expect, it } from "vitest";
import { calculateRisk, detectFindings } from "./index";

describe("risk engine", () => {
  it("raises risk for critical assets", () => expect(calculateRisk("high", "high", "critical", 1).riskScore).toBeGreaterThan(calculateRisk("high", "high", "low", 1).riskScore));
  it("detects missing security headers", () => {
    const findings = detectFindings({ assetValue: "example.com", knownAssets: ["example.com"], observations: [{ type: "http", data: { status: 200, securityHeaders: {} } }] });
    expect(findings.some((finding) => finding.ruleId === "missing-hsts")).toBe(true);
  });
  it("detects missing SPF and DMARC on mail-enabled domains", () => {
    const findings = detectFindings({ assetValue: "example.com", knownAssets: ["example.com"], observations: [{ type: "dns", data: { mx: [{ exchange: "mail.example.com", priority: 10 }], emailSecurity: { spfRecords: [], dmarcRecords: [], dmarcRecordName: "_dmarc.example.com" } } }] });
    expect(findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(["email-missing-spf", "email-missing-dmarc"]));
  });
  it("flags conservatively outdated exposed technology versions", () => {
    const findings = detectFindings({ assetValue: "example.com", knownAssets: ["example.com"], observations: [{ type: "http", data: { status: 200, securityHeaders: {}, technologies: ["Powered by: PHP/7.4.33"], technologyDetails: [{ name: "PHP", version: "7.4.33", source: "Powered by: PHP/7.4.33" }] } }] });
    expect(findings.some((finding) => finding.ruleId === "outdated-web-technology" && finding.confidence === "medium")).toBe(true);
  });
});
