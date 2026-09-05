import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { cagrilariGez, lineNo, lineText, ts } from "../core/ast.js";

/**
 * A03 — ReDoS (CWE-1333).
 *
 * A regular expression built from user input, or a regex with nested
 * unbounded quantifiers applied to user input, can be forced into
 * catastrophic backtracking — a denial of service. The clearest, least
 * noisy form is `new RegExp(<non-literal>)`: the pattern itself is
 * attacker-controlled.
 */

const INPUT_HINT =
  /(req\.|request\.|params|searchParams|query\.|body|formData|input|\.get\(|nextUrl|userInput|search|term|pattern)/i;

/** Catastrophic backtracking shape: nested/adjacent unbounded quantifiers. */
const CATASTROPHIC =
  /(\([^)]*[+*][^)]*\)[+*])|(\[[^\]]*\]\s*[+*]\s*\[[^\]]*\])|((?:[a-zA-Z0-9_]\s*[+*]\s*){2,})/;

export const redos: StaticRule = {
  id: "a03-redos",
  title: "Possible ReDoS: regex built from or applied to user input",
  owasp: "A03:2021-Injection",
  severity: "medium",
  cwe: "CWE-1333",
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

      cagrilariGez(ast, (c) => {
        // new RegExp(<non-literal>) → the pattern is dynamic.
        if (ts.isNewExpression(c) && ts.isIdentifier(c.expression) && c.expression.text === "RegExp") {
          const arg = c.arguments?.[0];
          if (!arg) return;
          const isLiteral = ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg);
          if (isLiteral) return;
          const line = lineNo(ast, c);
          const window = lines.slice(Math.max(0, line - 4), line + 2).join("\n");
          if (!INPUT_HINT.test(window)) return;
          findings.push({
            ruleId: this.id,
            title: "ReDoS: regular expression built from user input",
            owasp: this.owasp,
            severity: "medium",
            confidence: "likely",
            description:
              "new RegExp() is called with a non-literal pattern. If the pattern comes from user input, an attacker can supply a catastrophic pattern and stall the event loop.",
            evidence: [fileEvidence(file, line, lineText(ast, c))],
            remediation:
              "Never build a regex from user input. Use a fixed pattern and match the input against it, or escape user input before embedding.",
          });
          return;
        }

        // A regex literal with a catastrophic shape applied to user input.
        if (ts.isRegularExpressionLiteral(c.expression) || ts.isCallExpression(c)) {
          const e = c.expression;
          const reText = ts.isRegularExpressionLiteral(e) ? e.text : "";
          if (!reText || !CATASTROPHIC.test(reText)) return;
          const line = lineNo(ast, c);
          const window = lines.slice(Math.max(0, line - 4), line + 2).join("\n");
          if (!INPUT_HINT.test(window)) return;
          findings.push({
            ruleId: this.id,
            title: "ReDoS: catastrophic regex applied to user input",
            owasp: this.owasp,
            severity: "medium",
            confidence: "likely",
            description:
              "A regex with nested or adjacent unbounded quantifiers is applied near user input. On adversarial input this can backtrack exponentially and hang the process.",
            evidence: [fileEvidence(file, line, lineText(ast, c))],
            remediation:
              "Rewrite the pattern to avoid nested quantifiers (use atomic groups / possessive quantifiers where supported), and cap the input length.",
          });
        }
      });
    }
    return findings;
  },
};
