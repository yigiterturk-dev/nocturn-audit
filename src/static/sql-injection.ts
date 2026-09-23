import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { cagriAdi, lineText, lineNo, ts } from "../core/ast.js";

/**
 * A03 — SQL enjeksiyonu.
 *
 * ── Why the tree ──────────────────────────────────────────────────────────
 * As a text rule this produced 11 findings and nearly all were false: a
 * `.select()` chain, a `for (let from = 0; ...)` loop (because it contained
 * "from"), a `const passwordHash = await hashPassword(...)` line, and worst of
 * all Drizzle's `sql\`...\`` TAGGED TEMPLATE — which is precisely the construct
 * that turns interpolation into a bind parameter. The rule was reporting the
 * SOLUTION to injection as injection.
 *
 * Text cannot make this distinction, because the difference is syntactic:
 *   sql`SELECT * FROM t WHERE id = ${id}`   → TAGGED template: parameterised, SAFE
 *   db.query(`SELECT * FROM t WHERE id = ${id}`) → raw string: INJECTION
 * Both carry the same characters. What separates them is whether the template
 * is bound to a tag, or handed as an argument to a raw query call.
 *
 * So the rule now asks one question on the tree: is a string CONTAINING
 * INTERPOLATION OR CONCATENATION passed to a RAW QUERY SINK?
 */

/** Calls that bypass parameterisation — a string given to these goes through raw. */
const RAW_SINKS = new Set([
  "query",
  "execute",
  "executeRaw",
  "queryRaw",
  "$queryRawUnsafe",
  "$executeRawUnsafe",
  "raw",
  "unsafe",
  "prepare",
]);

/** Is this a real SQL statement? (the single word "from" is not enough) */
const SQL_IFADE =
  /\bSELECT\b[\s\S]{0,200}?\bFROM\b|\bINSERT\s+INTO\s+["'`]?\w|\bUPDATE\s+[\w."`]+[\s\S]{0,80}?\bSET\b|\bDELETE\s+FROM\s+["'`]?\w|\bDROP\s+TABLE\b|\bALTER\s+TABLE\b/i;

const GIRDI_IZI = /req\.|request\.|params|searchParams|query\.|body|formData|input/;

/**
 * The "dynamic UPDATE" shape: a column list built from an object's own keys,
 * where every VALUE is still a placeholder.
 *
 *   sqlite.prepare(`UPDATE t SET ${cols.map((k) => `${k} = ?`).join(", ")} WHERE id = ?`)
 *
 * Only the column NAMES are interpolated, and in practice they come from a
 * server-side object literal, not from the request. Two of these were reported
 * as CERTAIN sql-injection in clinentra — the word "input" appearing anywhere in
 * the surrounding text was enough to promote the finding. A `certain` label that
 * turns out to be wrong costs more than a missed `likely` one: it is the label
 * people act on without checking, so this shape may never claim certainty.
 */
const PARAMETRELI_SUTUN_LISTESI =
  /\.map\s*\([\s\S]{0,60}?=>[\s\S]{0,60}?`\$\{[^}]+\}\s*=\s*(?:\?|\$\d+)\s*`[\s\S]{0,40}?\.join\s*\(/;
// NOTE: the parameter list cannot be matched with `[^)]*` — `.map((key) => ...)`
// closes a paren before the arrow, so the first version of this regex never
// fired on the very code it was written for. Non-greedy [\s\S] spans instead.

/** Is this expression a SQL string carrying a variable? */
function isDangerousText(n: ts.Expression, source: ts.SourceFile): { text: string } | null {
  // `\`... ${x} ...\`` — an UNTAGGED template (a tagged one is a different node
  // type and never reaches here: TaggedTemplateExpression ≠ TemplateExpression).
  if (ts.isTemplateExpression(n)) {
    const text = n.getText(source);
    return SQL_IFADE.test(text) ? { text } : null;
  }
  // "SELECT ... " + x  → string concatenation
  if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const text = n.getText(source);
    if (!SQL_IFADE.test(text)) return null;
    // If either side is NOT a literal, a variable is entering.
    const sabit = (e: ts.Expression) => ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e);
    if (sabit(n.left) && sabit(n.right)) return null;
    return { text };
  }
  return null;
}

export const sqlInjection: StaticRule = {
  id: "a03-sql-injection",
  title: "Possible SQL injection (parameterisation bypassed)",
  owasp: "A03:2021-Injection",
  severity: "high",
  cwe: "CWE-89",
  kind: "static",
  // The tree is required: the tagged/untagged distinction is syntactic.
  requires: ["js"],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      // Generated client code (Prisma) is not project code.
      if (/(^|\/)(generated|\.prisma)\//.test(file.replace(/\\/g, "/"))) continue;
      const ast = ctx.ast(file);
      if (!ast) continue;

      const gez = (n: ts.Node): void => {
        if (ts.isCallExpression(n)) {
          const ad = cagriAdi(n);
          const son = ad.includes(".") ? ad.split(".").pop()! : ad;
          if (RAW_SINKS.has(son) || RAW_SINKS.has(ad)) {
            for (const arg of n.arguments) {
              const tehlike = isDangerousText(arg, ast.source);
              if (!tehlike) continue;
              // Column names built from an object's keys, with placeholders for
              // every value: the parameterisation was NOT bypassed.
              const sutunListesi = PARAMETRELI_SUTUN_LISTESI.test(tehlike.text);
              const hasInput = !sutunListesi && GIRDI_IZI.test(tehlike.text);
              findings.push({
                ruleId: "a03-sql-injection",
                title: "Possible SQL injection (parameterisation bypassed)",
                owasp: "A03:2021-Injection",
                severity: hasInput ? "high" : sutunListesi ? "low" : "medium",
                cwe: "CWE-89",
                confidence: hasInput ? "certain" : "likely",
                description:
                  `\`${ad}\` is called with a SQL string that has variables interpolated into it. ` +
                  "This call bypasses parameterisation: the query is whatever the string says." +
                  (hasInput
                    ? " The string shows request input (req/params/body) — direct injection."
                    : " Trace where the variable comes from; if any path reaches user input, this is injection."),
                evidence: [fileEvidence(file, lineNo(ast, n), lineText(ast, n))],
                remediation:
                  "Use parameterised queries: the tagged `sql` template (Drizzle, postgres.js), " +
                  "`db.query(text, [params])`, or Prisma's parameterised API. If you must use `$queryRawUnsafe` or `sql.raw`, " +
                  "validate the value against an allowlist — escaping is not enough.",
                remediationCode:
                  "// WRONG: db.query(`SELECT * FROM t WHERE id = ${id}`)\n" +
                  "// RIGHT: db.query('SELECT * FROM t WHERE id = $1', [id])\n" +
                  "// RIGHT: sql`SELECT * FROM t WHERE id = ${id}`  // tagged template = bind parameter",
              });
            }
          }
        }
        ts.forEachChild(n, gez);
      };
      gez(ast.source);
    }
    return findings;
  },
};
