import { describe, it, expect } from "vitest";
import { isTestOrFixture } from "../src/core/test-files.js";
import { isInsideRegexLiteral } from "../src/core/regex-literal.js";

/**
 * Precision infrastructure.
 *
 * This file encodes the two false-positive families that surfaced when the tool
 * was run ON ITSELF. Neither is peculiar to us: the same happens in every project
 * that keeps a fake key in its fixtures and has an input validator.
 */

describe("test/fixture surface is recognised", () => {
  it("test and fixture files are flagged", () => {
    for (const path of [
      "test/static-rules.test.ts",
      "tests/login-api.test.mjs",
      "src/__tests__/x.ts",
      "src/__fixtures__/keys.json",
      "e2e/checkout.spec.ts",
      "cypress/e2e/a.cy.ts",
      "components/Button.stories.tsx",
    ]) {
      expect(isTestOrFixture(path), path).toBe(true);
    }
  });

  it("production files are not flagged", () => {
    for (const path of [
      "src/static/sql-injection.ts",
      "app/api/orders/route.ts",
      "lib/auth.ts",
      // "latest" contains "test" but is not a test file.
      "lib/latest-run.ts",
      // nor is "protest".
      "app/protest/page.tsx",
    ]) {
      expect(isTestOrFixture(path), path).toBe(false);
    }
  });
});

describe("a pattern definition does not count as code", () => {
  it("a match inside a regex literal is skipped", () => {
    const line = `const TEHLIKE = /child_process|exec\\(/;`;
    const sutun = line.indexOf("child_process");
    expect(isInsideRegexLiteral(line, sutun)).toBe(true);
  });

  it("one inside new RegExp(\"...\") is skipped too", () => {
    const line = `const re = new RegExp("service_role", "i");`;
    expect(isInsideRegexLiteral(line, line.indexOf("service_role"))).toBe(true);
  });

  it("a REAL call is not skipped", () => {
    const line = `const { exec } = require("child_process"); exec(cmd);`;
    expect(isInsideRegexLiteral(line, line.indexOf("child_process"))).toBe(false);
  });

  it("a division is not mistaken for a regex", () => {
    // `a / b` is not a literal; if it were mistaken for one, half the line would go blind.
    const line = `const oran = toplam / adet; const key = "service_role";`;
    expect(isInsideRegexLiteral(line, line.indexOf("service_role"))).toBe(false);
  });

  it("real code AFTER a pattern on the same line is still seen", () => {
    const line = `if (/safe/.test(x)) { runCommand("child_process"); }`;
    expect(isInsideRegexLiteral(line, line.indexOf("safe"))).toBe(true);
    expect(isInsideRegexLiteral(line, line.indexOf("child_process"))).toBe(false);
  });
});

describe("plain text versus value", () => {
  it("message text is blanked out", async () => {
    const { blankNonCode } = await import("../src/core/sanitize.js");
    const line = `title: "child_process / a command is executed and this is risky",`;
    expect(blankNonCode(line)).not.toContain("child_process");
  });

  it("a REAL key is preserved — a secret is not a sentence", async () => {
    const { blankNonCode } = await import("../src/core/sanitize.js");
    const line = `const key = "sk_test_51H8xQ2Lkjhgfdsa";`;
    expect(blankNonCode(line)).toContain("sk_test_51H8xQ2Lkjhgfdsa");
  });

  it("a short value is preserved", async () => {
    const { blankNonCode } = await import("../src/core/sanitize.js");
    const line = `const cmd = "child_process";`;
    expect(blankNonCode(line)).toContain("child_process");
  });

  it("a template with interpolation is preserved — it may carry code", async () => {
    const { blankNonCode } = await import("../src/core/sanitize.js");
    const line = 'const q = `SELECT * FROM users WHERE id = ${id} AND x = 1`;';
    expect(blankNonCode(line)).toContain("SELECT");
  });

  it("line length and line count are preserved", async () => {
    const { blankNonCode } = await import("../src/core/sanitize.js");
    const source = `// comment\nconst a = /pattern/;\nconst b = "short";\n`;
    const cikti = blankNonCode(source);
    expect(cikti.length).toBe(source.length);
    expect(cikti.split("\n").length).toBe(source.split("\n").length);
  });
});

describe("coverage measurement — 'no findings' and 'could not look' are different", () => {
  it("unreadable languages are counted and the percentage drops", async () => {
    const { measureCoverage } = await import("../src/core/coverage.js");
    const { mkdtempSync, writeFileSync, mkdirSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    // Rust hala DESTEKLENMEYEN dil (Python 2026-08-24'te desteklendi).
    const root = mkdtempSync(join(tmpdir(), "kapsam-"));
    for (const ad of ["a.rs", "b.rs", "c.rs", "d.rs"]) writeFileSync(join(root, ad), "");
    writeFileSync(join(root, "schema.sql"), "");

    const k = measureCoverage(root);
    expect(k.readable).toBe(1);
    expect(k.okunamayan).toBe(4);
    expect(k.diller[0]).toEqual({ dil: "Rust", count: 4 });
    expect(k.yuzde).toBe(20);

    // Vendor directories are out of scope: the project did not write them and cannot fix them.
    mkdirSync(join(root, "venv"));
    writeFileSync(join(root, "venv", "x.py"), "");
    expect(measureCoverage(root).okunamayan).toBe(4);
  });

  it("no warning in a fully readable project", async () => {
    const { measureCoverage } = await import("../src/core/coverage.js");
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");

    const root = mkdtempSync(join(tmpdir(), "kapsam2-"));
    writeFileSync(join(root, "app.ts"), "");
    const k = measureCoverage(root);
    expect(k.okunamayan).toBe(0);
    expect(k.yuzde).toBe(100);
  });
});
