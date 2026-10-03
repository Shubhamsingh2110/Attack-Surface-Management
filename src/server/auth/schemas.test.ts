import { describe, expect, it } from "vitest";
import { loginSchema, strongPasswordSchema } from "./schemas";

describe("authentication schemas", () => {
  it("normalizes an admin email", () => {
    expect(loginSchema.parse({ email: "ADMIN@Example.COM", password: "value" }).email).toBe("admin@example.com");
  });

  it("accepts a strong password", () => {
    expect(strongPasswordSchema.safeParse("Strong-password-2026!").success).toBe(true);
  });

  it("rejects a weak password", () => {
    expect(strongPasswordSchema.safeParse("password").success).toBe(false);
  });
});
