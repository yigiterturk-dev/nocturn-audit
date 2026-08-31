import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { statusFromConfigNotProbe } from "../src/integrity/status-from-config-not-probe.js";

/**
 * Status derived from configuration.
 *
 * "Is the setting present?" and "does the service answer?" are two different
 * questions. Real case: a document scanner was dead for two days while the
 * dashboard said "ClamAV connected" the whole time — because it only looked at
 * whether the environment variable existed.
 */

const run = (files: Record<string, string>) =>
  statusFromConfigNotProbe.run(makeCtx(files)) as Array<{ severity: string; description: string }>;

describe("int — status derived from configuration", () => {
  it("BAD: a TURKISH claim is caught", () => {
    // The first version used the `\b` word boundary; in JavaScript that only knows
    // ASCII, and because the Turkish word `bağlı` ends in `ı` it NEVER matched.
    // The rule missed the very line it was written for.
    const f = run({
      "lib/scan.ts": `export function detay() {
  if (!scannerConfigured()) return "Tarayıcı yok.";
  return \`ClamAV bağlı: \${HOST()}\`;
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("THE PRESENCE OF A SETTING");
  });

  it("BAD: an English claim is caught too", () => {
    const f = run({
      "lib/db.ts": `export function status() {
  if (!process.env.DATABASE_URL) return "not configured";
  return "connected";
}`,
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: if it really probes, the claim is measured", () => {
    const f = run({
      "lib/db.ts": `export async function status() {
  if (!process.env.DATABASE_URL) return "not configured";
  await pool.query("select 1");
  return "connected";
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: no finding when the claim is scaled down", () => {
    // "configured" states what we saw; "connected" claims something we did not
    // measure. That is the correct fix and the rule must not punish it.
    const f = run({
      "lib/scan.ts": `export function detay() {
  if (!scannerConfigured()) return "Tarayıcı yok.";
  return \`ClamAV yapılandırıldı: \${HOST()}\`;
}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — the word boundary is correct", () => {
  it("CLEAN: 'disconnected' is not a connection CLAIM", () => {
    // The compound-word trap: without the boundary check, the "connected" inside
    // "disconnected" matches and the rule reports the exact opposite meaning.
    const f = run({
      "lib/db.ts": `export function status() {
  if (!process.env.DATABASE_URL) return "no config";
  return "disconnected";
}`,
    });
    expect(f.length).toBe(0);
  });
});
