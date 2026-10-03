import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decryptSecret, encryptSecret } from "./encryption";

describe("integration secret encryption", () => {
  it("round trips without storing plaintext", () => {
    const key = randomBytes(32).toString("base64");
    const encrypted = encryptSecret("sensitive-token", key);
    expect(encrypted).not.toContain("sensitive-token");
    expect(decryptSecret(encrypted, key)).toBe("sensitive-token");
  });
});
