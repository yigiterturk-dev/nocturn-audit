import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { cagrilariGez, lineNo, lineText, ts, type AstFile } from "../core/ast.js";

/**
 * A07 — JWT with the "none" algorithm (CWE-347).
 *
 * `jwt.verify(token, secret, { algorithms: ["none"] })` accepts unsigned
 * tokens — an attacker can forge a token with no signature. Also flagged:
 * an empty `algorithms` array (which some libraries treat as "any", including
 * none) and an explicit "none" entry.
 */

const JWT_MODULES = ["jsonwebtoken", "jose", "@hono/jwt", "njwt"];

/** Does the call resolve to a JWT library's verify/decode? */
function jwtVerifyMi(ast: AstFile, c: ts.CallExpression): boolean {
  const e = c.expression;
  if (ts.isIdentifier(e)) {
    const k = ast.ithal.get(e.text);
    return !!k && JWT_MODULES.includes(k.modul) && ["verify", "decode", "jwtVerify"].includes(k.disAd);
  }
  if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression)) {
    const k = ast.ithal.get(e.expression.text);
    if (!k || !JWT_MODULES.includes(k.modul)) return false;
    return k.disAd === "*" || k.disAd === "default"
      ? ["verify", "decode", "jwtVerify"].includes(e.name.text)
      : false;
  }
  return false;
}

/** Does the options object contain algorithms: ["none"] or algorithms: []? */
function algNoneMi(ast: ReturnType<typeof Object>, c: any): boolean {
  const opts = c.arguments[2];
  if (!opts || !ts.isObjectLiteralExpression(opts)) return false;
  for (const prop of opts.properties) {
    if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) continue;
    if (prop.name.text !== "algorithms") continue;
    const init = prop.initializer;
    if (!ts.isArrayLiteralExpression(init)) continue;
    const elems = init.elements.map((el) => el.getText(ast.source).replace(/["']/g, ""));
    if (elems.length === 0) return true; // empty array → "any algorithm"
    if (elems.some((e) => e.toLowerCase() === "none")) return true;
  }
  return false;
}

export const jwtAlgNone: StaticRule = {
  id: "a07-jwt-alg-none",
  title: "JWT verification accepts the 'none' algorithm",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "high",
  cwe: "CWE-347",
  kind: "static",
  requires: ["js"],
  confidence: "certain",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      const ast = ctx.ast(file);
      if (!ast) continue;
      cagrilariGez(ast, (c) => {
        if (!ts.isCallExpression(c)) return;
        if (!jwtVerifyMi(ast, c)) return;
        if (!algNoneMi(ast, c)) return;
        const line = lineNo(ast, c);
        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "high",
          confidence: "certain",
          description:
            "JWT verification is configured to accept the 'none' algorithm (or an empty algorithm list). An attacker can forge an unsigned token and pass authentication.",
          evidence: [fileEvidence(file, line, lineText(ast, c))],
          remediation:
            "Pin the allowed algorithms to a signed set (e.g. algorithms: ['HS256'] or ['RS256']) and never include 'none'.",
        });
      });
    }
    return findings;
  },
};
