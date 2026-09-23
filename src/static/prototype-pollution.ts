import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { lineNo, lineText, ts, type AstFile } from "../core/ast.js";

/**
 * A03 — Prototype pollution (CWE-1321).
 *
 * Assigning to `__proto__` / `constructor.prototype`, or merging user input
 * into an object with a recursive merge, lets an attacker pollute
 * Object.prototype and inject properties into every object in the process.
 */

const INPUT_HINT =
  /(req\.|request\.|params|searchParams|query\.|body|formData|input|\.get\(|nextUrl|userInput|payload|json)/i;

const MERGE_FNS = new Set(["merge", "deepMerge", "extend", "assign", "clone", "deepClone", "defaults"]);

export const prototypePollution: StaticRule = {
  id: "a03-prototype-pollution",
  title: "Possible prototype pollution",
  owasp: "A03:2021-Injection",
  severity: "medium",
  cwe: "CWE-1321",
  kind: "static",
  requires: ["js"],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      const ast = ctx.ast(file);
      if (!ast) continue;
      const content = ctx.read(file) ?? "";
      const lines = content.split(/\r?\n/);

      const gez = (n: ts.Node): void => {
        // obj["__proto__"] = ...  or  obj.constructor.prototype.x = ...
        if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          const lhs = n.left.getText(ast.source);
          if (/__proto__|constructor\s*\.\s*prototype|prototype\s*\.\s*__proto__/.test(lhs)) {
            const line = lineNo(ast, n);
            findings.push({
              ruleId: this.id,
              title: "Prototype pollution: assignment to __proto__ / constructor.prototype",
              owasp: this.owasp,
              severity: "high",
              confidence: "certain",
              description:
                "A direct assignment to __proto__ or constructor.prototype. If the key or value is user-controlled, this pollutes Object.prototype process-wide.",
              evidence: [fileEvidence(file, line, lineText(ast, n))],
              remediation:
                "Never write to __proto__ or constructor.prototype. Use a Map, or Object.create(null) for untrusted keys.",
            });
            return;
          }
        }

        // merge/extend/assign with a user-controlled source object.
        if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && MERGE_FNS.has(n.expression.text)) {
          const line = lineNo(ast, n);
          const window = lines.slice(Math.max(0, line - 4), line + 2).join("\n");
          if (!INPUT_HINT.test(window)) return;
          findings.push({
            ruleId: this.id,
            title: "Prototype pollution: recursive merge of user input",
            owasp: this.owasp,
            severity: "medium",
            confidence: "likely",
            description:
              "A merge/extend/assign call receives user-controlled data. A recursive merge that copies __proto__ keys can pollute Object.prototype.",
            evidence: [fileEvidence(file, line, lineText(ast, n))],
            remediation:
              "Use a merge that ignores __proto__/constructor keys, or validate the source object's keys before merging.",
          });
        }
        ts.forEachChild(n, gez);
      };
      gez(ast.source);
    }
    return findings;
  },
};
