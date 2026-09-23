import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A08 — two places write the same contract and one of them is untyped.
 *
 * When one side is `.ts` and the other `.mjs`/`.js`, the type system never
 * compares them. The shapes drift apart silently, and the reading side blows up
 * the moment it touches a missing field — usually in the place you would least
 * like to discover the failure.
 */
// Writing JSON metadata takes two shapes: a call with `.json` somewhere in the
// path, or serialising with `JSON.stringify` and writing that. The first version
// looked only for the former and missed the real case this rule EXISTS FOR — the
// path came from a helper function. It was running the rule against a real
// project, not a fixture, that showed this.
const YAZMA = /writeFile(?:Sync)?\s*\((?:[^)]*?\.json|[\s\S]{0,120}?JSON\.stringify)/;

export const contractTwoWriters: StaticRule = {
  id: "int-contract-two-writers",
  title: "Two writers share one metadata contract and one of them is untyped",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "medium",
  kind: "static",
  // The rule's own code filters by JS/TS extension — in a Python or Go project it
  // can look at no file at all. Undeclared, it would return `[]` and read as "clean".
  requires: ["js"],
  confidence: "likely",
  run(ctx): Finding[] {
    const tipli: string[] = [];
    const tipsiz: string[] = [];
    for (const file of ctx.files) {
      if (/\.(test|spec)\./.test(file)) continue;
      const content = ctx.read(file);
      if (!content || !YAZMA.test(content)) continue;
      if (/\.tsx?$/.test(file)) tipli.push(file);
      else if (/\.(mjs|cjs|js)$/.test(file)) tipsiz.push(file);
    }
    if (!tipli.length || !tipsiz.length) return [];

    // We look for a signal that the two writers write the SAME contract.
    // Otherwise any .ts and any .mjs JSON writer in the project got paired up and
    // unrelated files produced findings.
    //
    // The first attempt looked for shared `key:` literals and went blind on exactly
    // the case it should have caught: the typed side writes `JSON.stringify(summary)`,
    // so there are no key literals at all. The shared signal is not the key but the
    // IDENTIFIER — the fields both sides name (`fileName`, `checksum`…).
    const GURULTU = new Set([
      "await", "const", "return", "async", "function", "export", "import",
      "writeFile", "writeFileSync", "JSON", "stringify", "parse", "null",
      "string", "number", "readFile", "require", "module", "process",
    ]);
    const tanimlayicilar = (source: string): Set<string> =>
      new Set(
        [...source.matchAll(/\b([A-Za-z_]\w{4,})\b/g)]
          .map((m) => m[1])
          .filter((ad) => !GURULTU.has(ad)),
      );
    const sharedName = tipli.some((t) => {
      const a = tanimlayicilar(ctx.read(t) || "");
      return tipsiz.some((m) => {
        const b = tanimlayicilar(ctx.read(m) || "");
        for (const ad of b) if (a.has(ad)) return true;
        return false;
      });
    });
    if (!sharedName) return [];

    return [{
      ruleId: "int-contract-two-writers",
      title: "Two writers share one metadata contract and one of them is untyped",
      owasp: "A08:2021-Software & Data Integrity Failures",
      severity: "medium",
      confidence: "likely",
      description:
        `The JSON metadata is written from both typed (${tipli.slice(0, 3).join(", ")}) and untyped ` +
        `(${tipsiz.slice(0, 3).join(", ")}) files. The type system never compares the two, ` +
        "so the shapes can drift apart silently.",
      evidence: [fileEvidence(tipsiz[0], 1, "untyped writer"), fileEvidence(tipli[0], 1, "typed writer")],
      remediation:
        "Write a test that reads the contract from ONE source: derive the field list from the type " +
        "definition and assert the untyped writer emits all of them.",
    }];
  },
};
