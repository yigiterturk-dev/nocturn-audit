import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A05 — a statically generated page is dead under a `strict-dynamic` CSP.
 *
 * With `strict-dynamic`, the browser IGNORES the `'self'` allowance; the only
 * script that runs is one carrying a nonce. A nonce can only be emitted at
 * request time. If the page is statically generated the HTML arrives, the page
 * "loads", and no script runs at all.
 *
 * It is silent: unnoticeable in development, and in production the page is
 * simply dead.
 */
const NONCE_BAGI = /export const dynamic\s*=\s*["']force-dynamic["']|await connection\(\)|headers\(\)|cookies\(\)/;

const withoutComments = (src: string): string =>
  src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

export const staticPageStrictCsp: StaticRule = {
  id: "int-static-page-strict-csp",
  title: "Statically generated page under a strict-dynamic CSP; its scripts are blocked",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    // First, does the project actually use strict-dynamic? If not this rule does not apply.
    const strictDynamic = ctx.grep(/strict-dynamic/).length > 0;
    if (!strictDynamic) return [];

    const findings: Finding[] = [];
    for (const file of ctx.files) {
      const f = file.replace(/\\/g, "/");
      const eslesme = /(^|\/)(app|src\/app)\/(?:.*\/)?(page|not-found|error|global-error)\.(tsx|jsx)$/.exec(f);
      if (!eslesme) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const body = withoutComments(content);

      // error / global-error are MANDATORY client components: they CANNOT use
      // `connection()` or `force-dynamic` (they do not read route segment config).
      // But they do not fall into the trap either — Next never statically generates
      // an error boundary, it renders one in the context of a failed request (where
      // the nonce exists). And "use client" means a client boundary, which is out of
      // scope. So only an error boundary WITHOUT "use client" (one that could be
      // statically generated and left without a nonce) is flagged.
      const tur = eslesme[3];
      if (tur === "error" || tur === "global-error") {
        if (/^\s*["']use client["']/m.test(body)) continue;
      } else {
        // page / not-found: must be bound to request time.
        // COMMENTS ARE STRIPPED: a sentence mentioning `connection()` in a comment
        // would fool the rule into passing. This line exists because we fell into
        // that trap ourselves.
        if (NONCE_BAGI.test(body)) continue;
      }

      findings.push({
        ruleId: "int-static-page-strict-csp",
        title: "Statically generated page under a strict-dynamic CSP; its scripts are blocked",
        owasp: "A05:2021-Security Misconfiguration",
        severity: "medium",
        confidence: "likely",
        description:
          `\`${file}\` is not bound to request time, so it can be statically generated. Because the CSP uses \`strict-dynamic\`, ` +
          "none of the scripts on this page will run — the page loads, but it is dead.",
        evidence: [fileEvidence(file, 1, "force-dynamic / connection() yok")],
        remediation:
          "Bind the page to request time (`await connection()` or `export const dynamic = \"force-dynamic\"`), " +
          "then verify in the browser that the script count matches the nonce count.",
      });
    }
    return findings;
  },
};
