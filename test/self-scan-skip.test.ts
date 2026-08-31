import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { collectFiles } from "../src/core/engine.js";

/**
 * The tool's own rule source produced bait during a dogfood scan: the description
 * text inside `src/static/sql-injection.ts` was mistaken for SQL injection (it was
 * the single "high" finding in one run). The exception must apply ONLY in the
 * tool's own repository — another project's `src/static/` directory must be
 * scanned normally.
 */
function depoKur(paketAdi: string): string {
  const dir = mkdtempSync(join(tmpdir(), "selfscan-"));
  mkdirSync(join(dir, "src", "static"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: paketAdi }));
  writeFileSync(join(dir, "src", "static", "sql-injection.ts"), "export const x = 1;\n");
  writeFileSync(join(dir, "src", "app.ts"), "export const y = 2;\n");
  return dir;
}

describe("engine — the dogfood self-scan exception", () => {
  it("BAD: in the tool's own repository the rule source is skipped while the rest is scanned", async () => {
    const dir = depoKur("nocturn-audit");
    const files = await collectFiles(dir);
    expect(files.some((f) => f.includes("sql-injection.ts"))).toBe(false);
    expect(files.some((f) => f.endsWith("app.ts"))).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });

  it("GOOD: another project's src/static directory is scanned normally", async () => {
    const dir = depoKur("musteri-projesi");
    const files = await collectFiles(dir);
    expect(files.some((f) => f.includes("sql-injection.ts"))).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });
});
