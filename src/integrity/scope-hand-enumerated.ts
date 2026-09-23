import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A01 — the "pass everything through, then filter the listed ones" scoping pattern.
 *
 * A scoper shaped like `{ ...snapshot, a: filter(a), b: filter(b) }` passes EVERY
 * NEW collection through unfiltered unless someone adds it to the list. The leak
 * comes not from a missing gate but from the gate consulting a hand-written list
 * — and if the test enumerates the same list by hand, both blind spots face the
 * same way.
 */
const SCOPER_FUNCTION = /\b(scope|filterFor|restrictTo|forActor|kapsam)\w*\s*\(/i;

export const scopeHandEnumerated: StaticRule = {
  id: "int-scope-hand-enumerated",
  title: "The scoper works off a hand-listed set; a new collection leaks unfiltered",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.(ts|tsx|js|mjs)$/.test(file)) continue;
      if (/\.(test|spec)\./.test(file)) continue;
      const content = ctx.read(file);
      if (!content || !SCOPER_FUNCTION.test(content)) continue;

      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i += 1) {
        // an object starting with `return { ...snapshot,` or `...data,`
        if (!/\.\.\.\w+\s*,\s*$/.test(lines[i])) continue;
        // In the next 60 lines, how many keys are filtered by hand?
        const pencere = lines.slice(i + 1, i + 61).join("\n");
        const sayilanAnahtar = [...pencere.matchAll(/^\s{2,}(\w+):\s*\w+\(/gm)].length;
        if (sayilanAnahtar < 8) continue;

        findings.push({
          ruleId: "int-scope-hand-enumerated",
          title: "The scoper works off a hand-listed set; a new collection leaks unfiltered",
          owasp: "A01:2021-Broken Access Control",
          severity: "high",
          confidence: "likely",
          description:
            `\`${file}:${i + 1}\` spreads the whole object first, then filters ${sayilanAnahtar} key(s) by hand. ` +
            "A new collection that nobody adds to the list passes through unfiltered, leaking out-of-scope data.",
          evidence: [fileEvidence(file, i + 1, lines[i].trim())],
          remediation:
            "Derive the key list from the type or schema, or write a test that walks the ENTIRE response " +
            "and fails on any object carrying a forbidden id.",
        });
        break;
      }
    }
    return findings;
  },
};
