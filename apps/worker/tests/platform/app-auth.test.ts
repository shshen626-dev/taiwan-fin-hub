import { describe, expect, it } from "vitest";
import {
  clearSessionCookie,
  createSessionCookie,
  passwordMatches,
  verifyAppSession,
} from "../../src/platform/app-auth";
import type { Env } from "../../src/platform/env";

const env = {
  APP_AUTH_PASSWORD: "a-long-test-password",
  APP_AUTH_SECRET: "a-test-signing-secret-that-is-long-enough",
} as Env;

describe("application password authentication", () => {
  it("compares the configured password", async () => {
    await expect(passwordMatches("a-long-test-password", env)).resolves.toBe(
      true,
    );
    await expect(passwordMatches("wrong-password", env)).resolves.toBe(false);
  });

  it("creates and verifies a signed session cookie", async () => {
    const now = Date.UTC(2026, 8, 24);
    const cookie = await createSessionCookie(env, now);
    const request = new Request("https://example.com", {
      headers: { Cookie: cookie.split(";")[0]! },
    });

    await expect(verifyAppSession(request, env, now)).resolves.toBe(true);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
  });

  it("rejects tampered and expired sessions", async () => {
    const now = Date.UTC(2026, 8, 24);
    const cookie = await createSessionCookie(env, now);
    const value = cookie.split(";")[0]!;
    const tampered = `${value.slice(0, -1)}x`;

    await expect(
      verifyAppSession(
        new Request("https://example.com", { headers: { Cookie: tampered } }),
        env,
        now,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyAppSession(
        new Request("https://example.com", { headers: { Cookie: value } }),
        env,
        now + 31 * 24 * 60 * 60 * 1000,
      ),
    ).resolves.toBe(false);
  });

  it("clears the session cookie", () => {
    expect(clearSessionCookie()).toContain("Max-Age=0");
  });
});
