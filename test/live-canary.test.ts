import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanProject } from "../src/core/engine.js";
import { allRules } from "../src/rules.js";
// @ts-expect-error - a plain JS helper
import { startVulnerableServer } from "./live-server.mjs";

/**
 * THE LIVE CANARY — the half of the tool that was never measured.
 *
 * The static rules were measured with `test/canary/`; the live rules were NOT
 * measured at all. And the reason was a bad one: four of our own sites sit behind
 * a Vercel bot wall the tool cannot reach. So 10 live rules had never been
 * verified in the field even once — we saw the "live tests skipped" line but
 * never knew whether the rules WORKED.
 *
 * Here a deliberately vulnerable local server is started and the tool is pointed
 * at it. No need to wait for a Vercel bypass token.
 */
let server: { url: string; kapat: () => void };
let project: string;
let findings: Set<string>;

beforeAll(async () => {
  server = await startVulnerableServer();
  // Live rules require `owned: true` — the authorisation gate. Legitimate here
  // because it is our own local server.
  project = mkdtempSync(join(tmpdir(), "live-canary-"));
  writeFileSync(join(project, "package.json"), JSON.stringify({ name: "live-canary" }));

  const rapor = await scanProject(
    { name: "live-canary", path: project, owned: true, url: server.url, stack: {} },
    allRules,
    { liveOnly: true },
  );
  findings = new Set(rapor.findings.map((f) => f.ruleId));
}, 120_000);

afterAll(() => {
  server?.kapat();
  if (project) rmSync(project, { recursive: true, force: true });
});

const yakalandi = (id: string) => findings.has(id);

describe("live canary — do the live rules actually work", () => {
  it("no security headers → finding", () => {
    expect(yakalandi("a05-live-security-headers")).toBe(true);
  });

  it("a cookie without Secure/HttpOnly/SameSite → finding", () => {
    expect(yakalandi("a02-live-transport-and-cookies")).toBe(true);
  });

  it(".env / .git exposed → finding", () => {
    expect(yakalandi("a05-live-exposed-files")).toBe(true);
  });

  it("a database or env backup exposed → finding", () => {
    expect(yakalandi("a05-live-exposed-secrets")).toBe(true);
  });

  it("an admin endpoint answering without credentials → finding", () => {
    expect(yakalandi("a01-live-open-admin-endpoints")).toBe(true);
  });

  it("the health endpoint returns 500 → finding", () => {
    expect(yakalandi("int-live-health-endpoints")).toBe(true);
  });

  it("no login throttling / user enumeration leak → finding", () => {
    expect(yakalandi("a07-live-login-hardening")).toBe(true);
  });

  it("input reflected without encoding → finding", () => {
    expect(yakalandi("a03-live-reflected-input")).toBe(true);
  });

  it("a script without a nonce under a strict-dynamic CSP → finding (the page is silently dead)", () => {
    expect(yakalandi("int-live-page-nonce-coverage")).toBe(true);
  });

  it("the site is served over plain HTTP → finding", () => {
    // This rule used to STAY SILENT on http:// addresses: the tool said nothing
    // about a site served unencrypted. The live canary exposed it.
    expect(yakalandi("a05-live-ssl-domain")).toBe(true);
  });

  it("ALL OF THEM: all 10 live rules must fire", () => {
    // On the static side the canary sits at 81%; on the live side 100%. There are
    // few live rules and all of them can be represented by one fake server.
    expect(findings.size).toBe(10);
  });
});
