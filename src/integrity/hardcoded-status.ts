import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import {
  catchIcinde,
  enclosingFunction,
  modulSabitiIcinde,
  isInConditionalBranch,
  reallyMeasures,
  ormAlanSeciminde,
  isTwoStateFlag,
  hasOppositeValue,
  lineText,
  lineNo,
  ts,
} from "../core/ast.js";

/**
 * A09 — status is NOT MEASURED, it is hardcoded.
 *
 * When a field returning health, readiness or connection status is bound to a
 * constant, it keeps saying the same thing after the thing it claims to measure
 * dies. The dashboard can read "connected" while the service has been down for
 * days — and nobody looks, because the screen looks fine.
 *
 * ── Why the tree ──────────────────────────────────────────────────────────
 * As a text rule this produced 22 findings across 5 projects, and ALL of them
 * were false. For three separate reasons:
 *   1. `{ status: "ok" }` sat inside a `try`; the measurement (`select 1`) was
 *      right above it and the catch branch returned 503 — correct code.
 *   2. `configured: false` was the answer of an `if (!stateDir)` branch.
 *   3. `select: { status: true }` was a Prisma FIELD SELECTION, not a claim.
 * Patching it with a line window failed; even ±25 lines was not enough, because
 * the `await` doing the measuring was 30 lines up. Widening the window is not
 * the fix: the question is not "what is written nearby" but "is this value the
 */

const DURUM_ALANLARI = new Set([
  "ready",
  "healthy",
  "connected",
  "configured",
  "available",
  "operational",
  "productionAllowed",
  "serviceReady",
  "isLive",
  "status",
]);

const IYI_DEGERLER = new Set(["ok", "ready", "live", "healthy", "connected", "configured"]);

const RELATED_FILE = (file: string): boolean =>
  /(health|status|readiness|system|monitor|diagnostic)/i.test(file.replace(/\\/g, "/")) &&
  /\.(ts|tsx|js|mjs)$/.test(file);

/** Is the value a constant status claim? (`true` / `"ok"` and friends) */
function isConstantStatusValue(n: ts.Expression): boolean {
  if (n.kind === ts.SyntaxKind.TrueKeyword || n.kind === ts.SyntaxKind.FalseKeyword) return true;
  if (ts.isStringLiteral(n)) return IYI_DEGERLER.has(n.text.toLowerCase());
  return false;
}

export const hardcodedStatus: StaticRule = {
  id: "int-hardcoded-status",
  title: "Status is hardcoded rather than measured",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "medium",
  kind: "static",
  // Needs the tree; in a file that cannot be parsed this rule can say nothing.
  requires: ["js"],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!RELATED_FILE(file)) continue;
      if (/\.(test|spec)\.|\/types?\.|\.d\.ts$/.test(file)) continue;
      // A liveness endpoint is legitimately constant: if the process can answer,
      // it is up, and there is nothing else to measure. A readiness endpoint is
      // NOT — that one has to measure its dependencies.
      if (/\/health\/live|liveness|\/healthz/.test(file.replace(/\\/g, "/"))) continue;

      const ast = ctx.ast(file);
      if (!ast) continue;

      const gez = (n: ts.Node): void => {
        if (
          ts.isPropertyAssignment(n) &&
          ts.isIdentifier(n.name) &&
          DURUM_ALANLARI.has(n.name.text) &&
          isConstantStatusValue(n.initializer)
        ) {
          // 1) An ORM field selection → a data request, not a status claim.
          if (ormAlanSeciminde(n)) return;
          // 2) A catch branch → the MEASURED answer to a failure.
          if (catchIcinde(n)) return;
          // 3) A named constant at module level → a template value.
          if (modulSabitiIcinde(n)) return;
          // 4) If the enclosing function really measures something (await/try),
          //    this value is a branch's answer.
          if (reallyMeasures(enclosingFunction(n))) return;
          // 5) The answer of a conditional branch → a decision, not a claim. (The
          //    measurement may have happened above and arrived as a parameter:
          //    pure summarisers.)
          if (isInConditionalBranch(n)) return;
          // 6a) If the field is defined at MODULE level as a two-state flag (a
          //     boolean in the interface plus both true and false returns in the
          //     file), this is a status label. Pure transformers return the flag's
          //     "success" end; the measurement happened in the caller's fetch.
          if (isTwoStateFlag(ast, n.name.text)) return;
          // 6b) If the OPPOSITE value of the field is also returned in the same
          //    function, this is a branch outcome (the function returns its failure path too).
          {
            const v = n.initializer;
            const deger = ts.isStringLiteral(v) ? v.text : v.getText(ast.source);
            if (hasOppositeValue(enclosingFunction(n), n.name.text, deger)) return;
          }

          findings.push({
            ruleId: "int-hardcoded-status",
            title: "Status is hardcoded rather than measured",
            owasp: "A09:2021-Security Logging & Monitoring Failures",
            severity: "medium",
            confidence: "likely",
            description:
              `\`${file}:${lineNo(ast, n)}\` binds a status field (${n.name.text}) to a constant ` +
              "and the enclosing function shows no sign of measurement (no await, no try). A hardcoded " +
              "status stays the same after the thing it claims to measure breaks: the dashboard says healthy while the system is down.",
            evidence: [fileEvidence(file, lineNo(ast, n), lineText(ast, n))],
            remediation:
              "Derive the value from a real measurement: open the connection, run the query, probe the service. " +
              "If it cannot be measured, return 'unknown' — never 'healthy'.",
          });
        }
        ts.forEachChild(n, gez);
      };
      gez(ast.source);
    }
    return findings;
  },
};
