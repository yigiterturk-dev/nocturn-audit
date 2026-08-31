import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { collectFiles } from "../src/core/engine.js";
import { allRules } from "../src/rules.js";

describe("engine — minified/vendor JS is not scanned", () => {
  it("minified JS (one enormous line) does not enter collectFiles, ordinary JS does", async () => {
    const dir = mkdtempSync(join(tmpdir(), "min-"));
    mkdirSync(join(dir, "static"), { recursive: true });
    // minified: one enormous line (like tailwind)
    writeFileSync(join(dir, "static", "vendor.js"), "(()=>{" + "var x=1;".repeat(400) + "})();");
    // a .min.js name
    writeFileSync(join(dir, "static", "lib.min.js"), "console.log(1)");
    // normal kaynak
    writeFileSync(join(dir, "app.js"), "function f(){\n  return 1;\n}\n");
    const files = await collectFiles(dir);
    expect(files).toContain("app.js");
    expect(files.some((f) => f.includes("vendor.js"))).toBe(false); // minified by content
    expect(files.some((f) => f.includes("lib.min.js"))).toBe(false); // isim .min
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("registry — pip-audit is registered (Python deps)", () => {
  it("a06-pip-audit is among the deps rules", () => {
    expect(allRules.some((r) => r.id === "a06-pip-audit")).toBe(true);
  });
});
