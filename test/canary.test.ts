import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { scanProject } from "../src/core/engine.js";
import { allRules } from "../src/rules.js";

/**
 * THE CANARY — the negative check that measures whether tightening a rule
 * The canary — the negative check that measures whether tightening a rule created BLINDNESS.
 * Until now only one direction was measured: did false positives go down? A
 * falling finding count is NOT good news on its own — a muted rule lowers it
 * too. This test asks the opposite question: in a deliberately vulnerable
 * project, do the rules still see?
 *
 * Every file under `test/canary/` carries a hole that a rule family MUST catch.
 * If a rule is tightened too far, the test here breaks and the cost of that
 * tightening becomes visible.
 */

const KANARYA = join(import.meta.dirname ?? __dirname, "canary");

async function canaryTara() {
  const rapor = await scanProject(
    // The stack has to be realistic: the RLS rule is only meaningful in Supabase
    // client projects and rightly looks for that.
    { name: "canary", path: KANARYA, owned: false, stack: { framework: "next", db: "supabase" } },
    allRules,
    { staticOnly: true, includeStandards: false, includeDeps: false },
  );
  return rapor;
}

let raporSozu: ReturnType<typeof canaryTara> | null = null;
const rapor = () => (raporSozu ??= canaryTara());

/** Did the rule produce at least one finding? */
async function yakaladiMi(ruleId: string): Promise<boolean> {
  const r = await rapor();
  return r.findings.some((f) => f.ruleId === ruleId);
}

describe("canary — are the deliberately left holes still seen", () => {
  it("HOLE 1: a DB-writing route with no auth", async () => {
    expect(await yakaladiMi("a01-api-route-auth-missing")).toBe(true);
  });

  it("HOLE 2: CSRF — cookie session plus a form body", async () => {
    expect(await yakaladiMi("a01-csrf-missing")).toBe(true);
  });

  it("HOLE 3: mass assignment — form data straight into the DB", async () => {
    expect(await yakaladiMi("a01-mass-assignment")).toBe(true);
  });

  it("HOLE 4: SQL injection — request input in a raw query", async () => {
    expect(await yakaladiMi("a03-sql-injection")).toBe(true);
  });

  it("HOLE 5: command injection — request input reaching the shell", async () => {
    expect(await yakaladiMi("a03-dangerous-execution-sink")).toBe(true);
  });

  it("HOLE 6: SSRF — the target host comes from the caller", async () => {
    expect(await yakaladiMi("a10-ssrf-user-controlled-request")).toBe(true);
  });

  it("HOLE 7: status is hardcoded rather than measured", async () => {
    expect(await yakaladiMi("int-hardcoded-status")).toBe(true);
  });

  it("HOLE 8: sensitive data in a plaintext column", async () => {
    expect(await yakaladiMi("a02-sensitive-data-plaintext")).toBe(true);
  });

  it("HOLE 9: an unguarded JSON.parse", async () => {
    expect(await yakaladiMi("a04-unguarded-json-parse")).toBe(true);
  });

  it("HOLE 10: a live API key embedded in code", async () => {
    expect(await yakaladiMi("a02-hardcoded-secret")).toBe(true);
  });

  it("HOLE 11+12: a weak JWT secret / a weak password hash", async () => {
    expect(await yakaladiMi("a02-weak-hash-or-jwt-secret")).toBe(true);
  });

  it("HOLE 13: an open redirect", async () => {
    expect(await yakaladiMi("a01-open-redirect")).toBe(true);
  });

  it("HOLE 14: decoding a JWT without verifying the signature", async () => {
    expect(await yakaladiMi("a07-jwt-weak-verification")).toBe(true);
  });

  it("HOLE 15: a forgeable client IP in a security decision", async () => {
    expect(await yakaladiMi("a07-spoofable-client-ip")).toBe(true);
  });

  it("HOLE 16: an unsigned webhook", async () => {
    expect(await yakaladiMi("a08-unverified-webhook")).toBe(true);
  });

  it("HOLE 17: an external script with no SRI", async () => {
    expect(await yakaladiMi("a08-external-script-no-sri")).toBe(true);
  });

  it("HOLE 18: a public table without RLS enabled", async () => {
    expect(await yakaladiMi("a01-missing-rls")).toBe(true);
  });

  it("HOLE 19: an in-memory rate limit (useless on serverless)", async () => {
    expect(await yakaladiMi("a04-inmemory-ratelimit-serverless")).toBe(true);
  });

  it("HOLE 20: no security headers in next.config", async () => {
    expect(await yakaladiMi("a05-missing-security-headers")).toBe(true);
  });

  it("HOLE 21: no rate limit on a sensitive endpoint (login)", async () => {
    expect(await yakaladiMi("a04-missing-rate-limit")).toBe(true);
  });

  it("HOLE 22: no audit logging on a sensitive endpoint", async () => {
    expect(await yakaladiMi("a09-missing-audit-logging")).toBe(true);
  });

  it("HOLE 23: a secret leaked to the client via NEXT_PUBLIC_", async () => {
    expect(await yakaladiMi("a02-next-public-secret-leak")).toBe(true);
  });

  it("HOLE 24: a paid API in an unbounded loop", async () => {
    expect(await yakaladiMi("a04-unbounded-paid-loop")).toBe(true);
  });

  it("HOLE 25: a SQL column/table name built by concatenation", async () => {
    expect(await yakaladiMi("a03-sql-identifier-injection")).toBe(true);
  });

  it("HOLE 26: a check-then-act race (SELECT → UPDATE/INSERT)", async () => {
    expect(await yakaladiMi("a04-check-then-act-upsert")).toBe(true);
  });

  it("HOLE 27: CASCADE declared with no foreign_keys PRAGMA", async () => {
    expect(await yakaladiMi("a04-fk-cascade-off")).toBe(true);
  });

  it("HOLE 28: no lock wait in multi-writer SQLite", async () => {
    expect(await yakaladiMi("a04-sqlite-no-busy-timeout")).toBe(true);
  });

  it("HOLE 29: a DDL error swallowed by a bare except", async () => {
    expect(await yakaladiMi("a09-swallowed-ddl-error")).toBe(true);
  });

  it("HOLE 30: the .env inventory (committed or gitignored)", async () => {
    expect(await yakaladiMi("a02-env-file-committed")).toBe(true);
  });

  it("HOLE 31: a key embedded in git history", async () => {
    expect(await yakaladiMi("a02-secrets-git-history")).toBe(true);
  });

  it("HOLE 32: an undocumented env variable", async () => {
    expect(await yakaladiMi("a05-build-config-health")).toBe(true);
  });

  it("HOLE 33: no security.txt", async () => {
    expect(await yakaladiMi("a09-security-txt-missing")).toBe(true);
  });

  it("HOLE 34: a monitor with no alert target", async () => {
    expect(await yakaladiMi("int-alert-target-missing")).toBe(true);
  });

  it("HOLE 35: connection status derived from env rather than a probe", async () => {
    expect(await yakaladiMi("int-status-from-config-not-probe")).toBe(true);
  });

  it("HOLE 36: access revoked while open sessions stay alive", async () => {
    expect(await yakaladiMi("int-session-revoke-missing")).toBe(true);
  });

  it("HOLE 37: updates blocked but deletes allowed", async () => {
    expect(await yakaladiMi("int-update-guard-without-delete")).toBe(true);
  });

  it("HOLE 38: the authorisation check runs after validation", async () => {
    expect(await yakaladiMi("int-permission-after-validation")).toBe(true);
  });

  it("HOLE 40: real people's data committed to the repository", async () => {
    expect(await yakaladiMi("a02-pii-in-repo")).toBe(true);
  });

  it("HOLE 41: personal data written to logs", async () => {
    expect(await yakaladiMi("int-pii-in-logs")).toBe(true);
  });

  it("HOLE 42: the test command enumerates files by hand; a new test silently never runs", async () => {
    expect(await yakaladiMi("int-hand-enumerated-test-list")).toBe(true);
  });

  it("HOLE 43: special-category personal data detected", async () => {
    expect(await yakaladiMi("kvkk-special-category-data")).toBe(true);
  });

  it("HOLE 44: possible IDOR — direct object access with no ownership check", async () => {
    expect(await yakaladiMi("a01-idor-direct-object-reference")).toBe(true);
  });

  it("HOLE 45: the Supabase service_role key in use (RLS bypass)", async () => {
    expect(await yakaladiMi("a01-supabase-service-role-key")).toBe(true);
  });

  it("HOLE 46: insecure CORS configuration", async () => {
    expect(await yakaladiMi("a05-cors-misconfiguration")).toBe(true);
  });

  it("HOLE 47: backup and leftover files tracked or not gitignored", async () => {
    expect(await yakaladiMi("a05-backup-cruft-tracked")).toBe(true);
  });

  it("HOLE 48: backups taken with no restore rehearsal", async () => {
    expect(await yakaladiMi("int-backup-without-restore-rehearsal")).toBe(true);
  });

  it("HOLE 49: malware scanning happens after the file is written", async () => {
    expect(await yakaladiMi("int-scan-after-write")).toBe(true);
  });

  it("the canary must produce a CERTAIN high finding (the tool must not stay silent)", async () => {
    const r = await rapor();
    expect(r.findings.length).toBeGreaterThanOrEqual(52);
  });
});

/**
 * The tool's own canary (a deliberately planted fake Stripe key) was reported as
 * CERTAIN CRITICAL in its own git history. When the first critical finding an
 * audit tool shows you is its own test data, the team's trust dies on day one.
 * We do not mute it — we lower the severity and say what to do.
 */
describe("a secret on a fixture path: not critical, low with an explanation", () => {
  it("test/fixture/canary paths count as fixtures", async () => {
    const { fixturePath } = await import("../src/static/secrets-git-history.js");
    expect(fixturePath("test/canary/src/lib/gizli.ts")).toBe(true);
    expect(fixturePath("tests/fixtures/keys.ts")).toBe(true);
    expect(fixturePath("src/lib/auth.test.ts")).toBe(true);
    expect(fixturePath("__tests__/a.ts")).toBe(true);
    expect(fixturePath("examples/d1/app/route.ts")).toBe(true);
  });

  it("real source paths do NOT count as fixtures (a leak is never muted)", async () => {
    const { fixturePath } = await import("../src/static/secrets-git-history.js");
    expect(fixturePath("scripts/dump-schema.mjs")).toBe(false);
    expect(fixturePath("src/lib/gizli.ts")).toBe(false);
    expect(fixturePath("app/api/auth/route.ts")).toBe(false);
    expect(fixturePath("src/latest/config.ts")).toBe(false);
  });
});
