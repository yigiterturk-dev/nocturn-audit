import { describe, it, expect } from "vitest";
import { allRules } from "../src/rules.js";
import { REQUIREMENT_REASON } from "../src/core/measurement.js";
import { scanProject } from "../src/core/engine.js";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * The tool's three most dangerous mistakes (mistaking a challenge page for the
 * app, looking for headers in a 308 redirect, hitting an origin gate and calling
 * it "no rate limit") came from a single defect: returning `[]` meant both "I
 * looked and it is clean" and "I could not look". The contract separates them —
 */
describe("the measurement contract", () => {
  it("EVERY rule must declare its preconditions", () => {
    const beyansiz = allRules.filter((r) => !Array.isArray(r.requires));
    expect(beyansiz.map((r) => r.id)).toEqual([]);
  });

  it("every declared requirement must be defined (a typo must not silently mute a rule)", () => {
    const gecerli = new Set(Object.keys(REQUIREMENT_REASON));
    const hatali = allRules.flatMap((r) =>
      r.requires.filter((g) => !gecerli.has(g)).map((g) => `${r.id}: ${g}`),
    );
    expect(hatali).toEqual([]);
  });

  it("rules needing git do not run outside a git REPOSITORY and are reported as gaps", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sozlesme-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x" }));
    writeFileSync(join(dir, "index.ts"), `export const a = 1;\n`);

    const rapor = await scanProject(
      { name: "x", path: dir, owned: false, stack: {} },
      allRules,
      { staticOnly: true, includeStandards: false },
    );

    const gitBosluklari = rapor.gaps.filter((b) => b.requirement === "git");
    // Not a repository → the git rules do not say "clean", they say "could not measure".
    expect(gitBosluklari.length).toBeGreaterThan(0);
    for (const b of gitBosluklari) {
      expect(b.reason).toBeTruthy();
      // A rule that fell into the gap cannot have been executed.
      expect(rapor.rulesRun).not.toContain(b.ruleId);
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it("the RLS rule does not say 'clean' in a project with no SQL file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sozlesme-sql-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x" }));
    writeFileSync(join(dir, "index.ts"), `export const a = 1;\n`);

    const rapor = await scanProject(
      { name: "x", path: dir, owned: false, stack: {} },
      allRules,
      { staticOnly: true, includeStandards: false },
    );
    const sqlBosluk = rapor.gaps.find((b) => b.requirement === "sql");
    expect(sqlBosluk).toBeDefined();
    rmSync(dir, { recursive: true, force: true });
  });
});
