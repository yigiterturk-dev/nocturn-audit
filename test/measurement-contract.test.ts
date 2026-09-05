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

/**
 * A missing project path is the same defect in its purest form: the tool CANNOT
 * LOOK, yet the report used to say "score 0 · no findings". A wrong path in
 * targets.json (project moved) would then read as GREEN for months.
 */
describe("a project path that does not exist", () => {
  it("does NOT report clean — it raises a certain HIGH finding", async () => {
    const yokYol = join(tmpdir(), "kesinlikle-olmayan-proje-" + Date.now());
    const rapor = await scanProject(
      { name: "hayalet", path: yokYol, owned: false } as never,
      allRules,
      { staticOnly: true },
    );
    const bulgu = rapor.findings.find((f) => f.ruleId === "int-scan-target-missing");
    expect(bulgu, "eksik yol icin bulgu uretilmeli").toBeTruthy();
    expect(bulgu!.severity).toBe("high");
    expect(bulgu!.confidence).toBe("certain");
    // En onemlisi: rapor BOS olmamali; bos rapor "temiz" diye okunur.
    expect(rapor.findings.length).toBeGreaterThan(0);
  });

  it("yol VAR ama kaynak dosya YOKSA da temiz demez (int-scan-target-empty)", async () => {
    // Gercek vaka: [KOD-ADI]-v2 klasorunde yalniz 2 log dosyasi vardi, kod baska
    // yerdeydi; rapor "score 0" diyordu.
    const dir = mkdtempSync(join(tmpdir(), "bos-proje-"));
    writeFileSync(join(dir, "launchd.err.log"), "sadece log\n");
    const rapor = await scanProject(
      { name: "bos", path: dir, owned: false } as never,
      allRules,
      { staticOnly: true },
    );
    const bulgu = rapor.findings.find((f) => f.ruleId === "int-scan-target-empty");
    expect(bulgu, "bos proje icin bulgu uretilmeli").toBeTruthy();
    expect(bulgu!.severity).toBe("high");
    rmSync(dir, { recursive: true, force: true });
  });

  it("var olan bir proje icin bu bulguyu URETMEZ (yanlis alarm degil)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gercek-proje-"));
    writeFileSync(join(dir, "index.js"), "export const x = 1;\n");
    const rapor = await scanProject(
      { name: "gercek", path: dir, owned: false } as never,
      allRules,
      { staticOnly: true },
    );
    expect(rapor.findings.some((f) => f.ruleId === "int-scan-target-missing")).toBe(false);
    expect(rapor.findings.some((f) => f.ruleId === "int-scan-target-empty")).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});

/**
 * A misspelled key in targets.json used to be swallowed in silence. `urls: [...]`
 * (correct: `url`) meant the live probes never ran — for months — and the report
 * still looked clean.
 */
describe("targets.json unknown key", () => {
  it("tanınmayan anahtar UYARI verir ve dogru adi onerir", async () => {
    const { loadRegistry } = await import("../src/registry.js");
    const dir = mkdtempSync(join(tmpdir(), "hedefler-"));
    const t = join(dir, "targets.json");
    writeFileSync(
      t,
      JSON.stringify({
        projects: [{ name: "x", path: dir, owned: true, urls: ["https://ornek.test"] }],
      }),
    );
    const uyarilar: string[] = [];
    const eski = console.warn;
    console.warn = (m?: unknown) => uyarilar.push(String(m));
    try {
      loadRegistry(t);
    } finally {
      console.warn = eski;
    }
    expect(uyarilar.join("\n")).toMatch(/urls/);
    expect(uyarilar.join("\n")).toMatch(/"url" mi demek istediniz/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("dogru anahtarlar icin UYARI VERMEZ", async () => {
    const { loadRegistry } = await import("../src/registry.js");
    const dir = mkdtempSync(join(tmpdir(), "hedefler-temiz-"));
    const t = join(dir, "targets.json");
    writeFileSync(
      t,
      JSON.stringify({
        $comment: "aciklama satiri uyari uretmemeli",
        projects: [{ name: "x", path: dir, owned: true, url: "https://ornek.test" }],
      }),
    );
    const uyarilar: string[] = [];
    const eski = console.warn;
    console.warn = (m?: unknown) => uyarilar.push(String(m));
    try {
      loadRegistry(t);
    } finally {
      console.warn = eski;
    }
    expect(uyarilar).toEqual([]);
    rmSync(dir, { recursive: true, force: true });
  });
});
