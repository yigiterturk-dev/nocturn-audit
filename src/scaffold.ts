import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

/**
 * NEW RULE SCAFFOLD.
 *
 * The three requirements for writing a rule are documented: a BAD fixture, a
 * CLEAN fixture, a `requires` declaration. But documentation does not get read —
 * least of all in the moment of "let me just add a quick rule". So the discipline
 * does not live in the docs, it lives in the GENERATED FILES:
 *
 *  • The rule file arrives with `requires: []` (the declaration is mandatory, an
 *    empty array is a valid one).
 *  • The test file arrives with BAD and CLEAN fixtures and BOTH START FAILING.
 *    The rule cannot go green until they are filled in.
 *  • What to add to the canary is printed to the screen.
 *
 * This exists so that everything learned today does not have to be relearned by
 * everyone else.
 */

const RULE_TEMPLATE = (id: string, varName: string, title: string) => `import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * ${title}
 *
 * TODO: write down WHY this rule exists. Which real incident produced it?
 * The rationale outlives the pattern: patterns change, but the rationale tells
 * the next person what this protects.
 */
export const ${varName}: StaticRule = {
  id: "${id}",
  title: "${title}",
  owasp: "A04:2021-Insecure Design", // TODO: pick the right OWASP category
  severity: "medium",
  kind: "static",
  /**
   * PRECONDITIONS — what does this rule need in order to measure anything?
   *
   * An empty array is a valid declaration ("I have no preconditions"). But if you
   * genuinely need something, DECLARE it: when it is unmet the engine skips the
   * rule entirely and the report says "not measured". Without a declaration, a
   * \`[]\` return in an environment that cannot satisfy the rule reads as "clean"
   * — the most dangerous mistake this tool can make.
   *
   * Options: "git" | "live" | "npm" | "net" | "js" | "python" | "sql"
   */
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      const content = ctx.read(file);
      if (!content) continue;

      // TODO: detection logic.
      //
      // THINK BEFORE REACHING FOR TEXT SEARCH: is the question "does this pattern
      // appear", or "what does this call target / where does this value come from /
      // which branch is this literal in"? The second kind cannot be answered with
      // text; use \`ctx.ast(file)\` (see core/ast.ts). Most false positives in this
      // tool came from structural questions asked with text search.
      void content;
      void file;
      void findings.push;
    }

    return findings;
  },
};

// TODO: delete this — it is how the test knows the scaffold is still unfilled.
export const SCAFFOLD_NOT_FILLED = true;

function exampleFinding(file: string, line: number, snippet: string): Finding {
  return {
    ruleId: "${id}",
    title: "${title}",
    owasp: "A04:2021-Insecure Design",
    severity: "medium",
    confidence: "likely",
    description: "TODO: what does the finding say, why does it matter, what happens?",
    evidence: [fileEvidence(file, line, snippet)],
    remediation: "TODO: what will the reader DO? Write a concrete step.",
  };
}
void exampleFinding;
`;

const TEST_SABLONU = (id: string, varName: string, path: string) => `import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { ${varName} } from "../${path}";

const run = (files: Record<string, string>) =>
  ${varName}.run(makeCtx(files)) as Array<{ severity: string }>;

/**
 * ${id}
 *
 * THREE REQUIREMENTS — the rule does not enter the system until all three are met:
 *  1. A BAD fixture: a realistic example the rule MUST catch.
 *  2. A CLEAN fixture: something that LOOKS like it but must NOT be caught.
 *     This is the hard one — false positives are always born here.
 *  3. The \`requires\` declaration (in the rule file).
 *
 * Also: when you tighten a rule, add a FIELD-SHAPED example of the hole to
 * \`test/canary/\`. A fixture is what the author imagined; the canary is what the
 * field looks like. They differ — the day the canary was built, a rule whose
 * fixtures all used \`req.json()\` turned out to no longer see form bodies at all.
 */
describe("${id}", () => {
  it("BAD: an example that must be caught", () => {
    const f = run({
      // TODO: write a realistic file that CARRIES the vulnerability.
      "src/example.ts": \`export const TODO = "fill in this fixture";\`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("CLEAN: a lookalike that must NOT be caught", () => {
    const f = run({
      // TODO: write a file that RESEMBLES the vulnerability but is safe.
      // (e.g. the same pattern with the guard present, or a different context)
      "src/example-clean.ts": \`export const TODO = "fill in this fixture too";\`,
    });
    expect(f.length).toBe(0);
  });

  it("scaffold filled in (this test fails until the TODOs are gone)", async () => {
    const mod = await import("../${path}");
    expect(
      (mod as Record<string, unknown>).SCAFFOLD_NOT_FILLED,
      "The rule scaffold is still unfilled: finish the TODOs in the src file and delete the SCAFFOLD_NOT_FILLED line.",
    ).toBeUndefined();
  });
});
`;

export function scaffoldRule(id: string): { written: string[]; warning?: string } {
  if (!/^[a-z0-9]+(-[a-z0-9]+)+$/.test(id)) {
    return { written: [], warning: `Invalid rule id: "${id}". Format: a01-example-rule / int-example-rule` };
  }
  const slug = id.replace(/^(a\d{2}|int|kvkk)-/, "");
  const varName = slug.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
  const dizin = id.startsWith("int-") ? "src/integrity" : "src/static";
  const rulePath = join(dizin, `${slug}.ts`);
  const testYolu = join("test", `rule-${slug}.test.ts`);
  const title = slug.replace(/-/g, " ").replace(/^./, (c) => c.toUpperCase());

  if (existsSync(rulePath)) return { written: [], warning: `Already exists: ${rulePath}` };

  mkdirSync(dirname(rulePath), { recursive: true });
  writeFileSync(rulePath, RULE_TEMPLATE(id, varName, title));
  writeFileSync(testYolu, TEST_SABLONU(id, varName, rulePath.replace(/\.ts$/, ".js")));

  // Add it to the registry — forgetting to do that by hand means the rule
  // silently never runs. A silent rule is worse than a missing one: it is believed to exist.
  const regYolu = "src/rules.ts";
  let reg = readFileSync(regYolu, "utf-8");
  const importSatiri = `import { ${varName} } from "./${dizin.replace("src/", "")}/${slug}.js";`;
  if (!reg.includes(importSatiri)) {
    reg = reg.replace(
      /^(import type \{ Rule \} from "\.\/core\/rule\.js";)/m,
      `$1\n${importSatiri}`,
    );
    const dizi = id.startsWith("int-") ? /const integrityRules[^=]*=\s*\[/ : /const staticRules[^=]*=\s*\[/;
    if (dizi.test(reg)) reg = reg.replace(dizi, (m) => `${m}\n  ${varName},`);
    else reg = reg.replace(/export const allRules: Rule\[\] = \[/, (m) => `${m}\n  ${varName},`);
    writeFileSync(regYolu, reg);
  }

  return { written: [rulePath, testYolu, regYolu] };
}
