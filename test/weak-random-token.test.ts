import { describe, it, expect } from "vitest";
import { weakRandomToken } from "../src/static/weak-random-token.js";
import { makeCtx } from "./helpers.js";

const run = (files: Record<string, string>) =>
  weakRandomToken.run(makeCtx(files));

describe("a07-weak-random-token", () => {
  it("flags a session token built from Math.random", async () => {
    const findings = await run({
      "src/lib/session.ts": `export function newSession() {\n  const sessionToken = Math.random().toString(36).slice(2);\n  return sessionToken;\n}`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].owasp).toBe("A07:2021-Identification & Authentication Failures");
  });

  it("flags Date.now()-derived csrf values", async () => {
    const findings = await run({
      "src/lib/csrf.ts": `const csrf = Date.now().toString(36);`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
  });

  it("flags Python's random module on the auth surface", async () => {
    const findings = await run({
      "app/auth.py": `import random\notp = str(random.randint(100000, 999999))\nprint(otp)`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
  });

  it("measures a REAL CSPRNG's keyspace and flags a small draw", async () => {
    const findings = await run({
      "src/lib/otp.ts": `const otp = crypto.randomBytes(8).toString("hex");`,
    });
    expect(findings).toHaveLength(1);
    // 8 bytes = 64 bits = "marginal" per the Shannon core's bands
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].description).toContain("64 bits");
  });

  it("leaves proper randomness alone", async () => {
    const findings = await run({
      "src/lib/session.ts": `const sessionToken = crypto.randomBytes(32).toString("hex");\nconst id = crypto.randomUUID();\nconst nonce = crypto.getRandomValues(new Uint8Array(32));`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores Math.random in non-security contexts", async () => {
    const findings = await run({
      "src/lib/demo.ts": `const rotation = Math.random() * 360;\nconst delay = Date.now() - startedAt;`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores Turkish date arithmetic — 'nOnce' is NOT a nonce (real corpus case)", async () => {
    const findings = await run({
      "app/dashboard/page.tsx": `const ondortGunOnce = new Date(Date.now() - 14 * 86400000).toISOString();`,
      "app/basit/irsaliye/page.tsx": `const otuzGunOnce = new Date(Date.now() - 30 * 86400000).toISOString();`,
    });
    expect(findings).toHaveLength(0);
  });

  it("still catches a real camelCase nonce", async () => {
    const findings = await run({
      "src/lib/nonce.ts": `const csrfNonce = Math.random().toString(36).slice(2);`,
    });
    expect(findings).toHaveLength(1);
  });

  it("ignores data files entirely", async () => {
    const findings = await run({
      "data/tokens.csv": `token,Math.random(),otp`,
    });
    expect(findings).toHaveLength(0);
  });
});
