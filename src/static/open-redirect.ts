import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";
import { kapsamdaTanim, lineNo, ts } from "../core/ast.js";

/**
 * A01 — open redirect.
 *
 * A destination taken from user input (query/body/searchParams) is passed to a
 * redirect or location call without validation. This enables phishing and OAuth token theft.
 */

const REDIRECT_CALL =
  /\b(redirect|res\.redirect|NextResponse\.redirect|Response\.redirect|location\.(?:href|assign|replace)|window\.location\s*=|location\s*=)\s*[\(=]/i;

const USER_INPUT =
  /(req\.query|req\.body|req\.params|request\.(?:query|body)|searchParams\.get|nextUrl\.searchParams|url\.searchParams\.get|getQuery|\bparams\.[a-zA-Z_]|\bquery\.[a-zA-Z_])/;

// Signals of a safe redirect (when present in the file, reduce false positives).
const VALIDATION =
  /startsWith\(\s*["'`]\/|allowed?(?:Hosts|Redirects|Origins|Paths)|allowlist|allow[_-]?list|isSafeRedirect|safeRedirect|\.origin\s*===|new URL\([^)]*\)[^\n]*\.(?:origin|hostname|host)/i;

export const openRedirect: StaticRule = {
  id: "a01-open-redirect",
  title: "Unvalidated redirect (open redirect)",
  owasp: "A01:2021-Broken Access Control",
  severity: "medium",
  cwe: "CWE-601",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      // If the file has an explicit validation or allowlist, treat it as safe.
      if (VALIDATION.test(content)) continue;

      const lines = content.split(/\r?\n/);

      // TAINT IS FUNCTION SCOPED.
      //
      // A file-wide set was used first, and in large files it was a disaster: in
      // one project's 6000-line server.ts, a single `const url = req.query.x`
      // somewhere made EVERY `redirect(url)` call in the whole file tainted. An
      // Instagram OAuth redirect was declared an "open redirect" that way — even
      // though the destination was built from a fixed app id and its own
      // redirectUri.
      const tree = ctx.ast(file);
      const tainted = new Set<string>();
      if (!tree) {
        for (const raw of lines) {
          const dm = /\b(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*([^;]+)/.exec(raw);
          if (dm && USER_INPUT.test(dm[2])) tainted.add(dm[1]);
        }
      }

      /** Does the variable `name` on this line derive from input WITHIN ITS OWN function? */
      const kapsamdaZehirli = (lineIndex: number, ad: string): boolean => {
        if (!tree) return tainted.has(ad);
        let targetNode: ts.Node | null = null;
        const gez = (n: ts.Node): void => {
          if (targetNode) return;
          if (ts.isIdentifier(n) && n.text === ad && lineNo(tree, n) === lineIndex + 1)
            targetNode = n;
          else ts.forEachChild(n, gez);
        };
        gez(tree.source);
        if (!targetNode) return false;
        const tanim = kapsamdaTanim(targetNode, ad);
        if (!tanim?.initializer) return false;
        return USER_INPUT.test(tanim.initializer.getText(tree.source));
      };

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!REDIRECT_CALL.test(raw)) continue;

        const directInput = USER_INPUT.test(raw);
        // Extract the variable name from the redirect argument, then check whether
        // it is tainted IN ITS OWN scope.
        const argAd = /(?:redirect|location[^\n]*)[\(=]\s*[`${]*\s*([A-Za-z_$][\w$]*)/.exec(
          raw,
        )?.[1];
        const taintedArg = !directInput && !!argAd && kapsamdaZehirli(i, argAd);
        const oldTaint =
          !directInput &&
          !tree &&
          [...tainted].some((v) =>
            new RegExp(
              `(redirect|location[^\\n]*)[\\(=]\\s*(\`?\\$?\\{?)?${v}\\b`,
            ).test(raw),
          );

        if (directInput || taintedArg || oldTaint) {
          findings.push({
            ruleId: this.id,
            title: this.title,
            owasp: this.owasp,
            severity: "medium",
            cwe: this.cwe,
            description:
              "The redirect target comes straight from user input (query, body or searchParams) with no allowlist or same-origin check. An attacker can send users to an external site (phishing, OAuth token theft).",
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation:
              "Restrict the redirect target to permitted paths or origins: validate relative paths with `startsWith('/')`, or use a fixed allowlist.",
            remediationCode:
              "const target = searchParams.get('next') ?? '/';\n" +
              "if (!target.startsWith('/') || target.startsWith('//')) return redirect('/');\n" +
              "return redirect(target);",
          });
        }
      }
    }
    return findings;
  },
};
