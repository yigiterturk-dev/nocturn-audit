import { describe, it, expect } from "vitest";
import { blankNonCode } from "../src/core/sanitize.js";

/**
 * NESTED TEMPLATES — the silent blind spot.
 *
 * `blankNonCode` used to end a template at the next backtick. In
 * `` `SET ${cols.map((k) => `${k} = ?`).join(", ")}` `` that backtick belongs to
 * the INNER template, so the outer literal was declared finished and the rest of
 * the line was blanked. Two consequences, and the second is the dangerous one:
 *   1. clinentra's parameterised UPDATE was reported as CERTAIN sql-injection,
 *      because the `.join(", ")` proving it safe had been erased.
 *   2. Any real finding living in the erased tail could not be seen at all —
 *      the scan reads as clean because the code was never shown to the rules.
 */
describe("blankNonCode — nested templates", () => {
  it("keeps the code after an inner template intact", () => {
    const src =
      'const q = db.prepare(`UPDATE t SET ${cols.map((k) => `${k} = ?`).join(", ")} WHERE id = ?`);';
    expect(blankNonCode(src)).toBe(src);
  });

  it("keeps a quote inside an interpolation from ending the template", () => {
    const src = 'const s = `a ${x["}`"]} b`; const after = secret;';
    expect(blankNonCode(src)).toContain("const after = secret;");
  });

  it("preserves line and column positions", () => {
    const src = 'const q = `${a.map((k) => `${k}!`).join("")}`;\nconst next = 1;';
    const out = blankNonCode(src);
    expect(out.split("\n").length).toBe(src.split("\n").length);
    expect(out.length).toBe(src.length);
  });
});
