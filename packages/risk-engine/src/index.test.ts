import { describe, expect, it } from "vitest";
import { calculateRisk, detectFindings } from "./index";

describe("risk engine", () => {
  it("raises risk for critical assets", () => expect(calculateRisk("high", "high", "critical", 1).riskScore).toBeGreaterThan(calculateRisk("high", "high", "low", 1).riskScore));
  it("detects missing security headers", () => {
    const findings = detectFindings({ assetValue: "example.com", knownAssets: ["example.com"], observations: [{ type: "http", data: { status: 200, securityHeaders: {} } }] });
    expect(findings.some((finding) => finding.ruleId === "missing-hsts")).toBe(true);
  });
});
