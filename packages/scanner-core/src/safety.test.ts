import { describe, expect, it } from "vitest";
import { canonicalizeDomain, isPublicIp } from "./safety";

describe("scanner target safety", () => {
  it("canonicalizes domains", () => expect(canonicalizeDomain("HTTPS://Example.COM/path")).toBe("example.com"));
  it("blocks non-public addresses", () => {
    expect(isPublicIp("127.0.0.1")).toBe(false);
    expect(isPublicIp("169.254.169.254")).toBe(false);
    expect(isPublicIp("10.0.0.1")).toBe(false);
  });
  it("accepts public addresses", () => expect(isPublicIp("8.8.8.8")).toBe(true));
});
