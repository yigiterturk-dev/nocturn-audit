import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A05 (live) — `strict-dynamic` is in use but the page's scripts carry no nonce.
 *
 * This is the definitive signature of a statically generated page: the browser
 * ignores the `'self'` allowance and a script without a nonce does not run. The
 * page loads, the HTML arrives, nothing executes — and nothing shows up on an
 * error page.
 */
const scriptSayisi = (html: string): number => (html.match(/<script[\s>]/gi) || []).length;
const nonceSayisi = (html: string): number => (html.match(/<script[^>]*\snonce=/gi) || []).length;

export const livePageNonceCoverage: LiveRule = {
  id: "int-live-page-nonce-coverage",
  title: "Scripts without a nonce under a strict-dynamic CSP — the page is dead",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  confidence: "certain",
  async run(ctx): Promise<Finding[]> {
    const root = await ctx.probe("/");
    const csp = root.headers["content-security-policy"] || "";
    if (!/strict-dynamic/.test(csp)) return [];

    const findings: Finding[] = [];
    // The home page and a definitely-nonexistent path (the 404 page) — 404 is where this escapes most often.
    for (const path of ["/", "/nocturn-audit-olmayan-yol-probe"]) {
      const r = path === "/" ? root : await ctx.probe(path);
      if (!r.bodySnippet || !/<script/i.test(r.bodySnippet)) continue;
      const toplam = scriptSayisi(r.bodySnippet);
      const nonceli = nonceSayisi(r.bodySnippet);
      if (toplam === 0 || nonceli > 0) continue;

      findings.push({
        ruleId: "int-live-page-nonce-coverage",
        title: "Scripts without a nonce under a strict-dynamic CSP — the page is dead",
        owasp: "A05:2021-Security Misconfiguration",
        severity: "medium",
        confidence: "certain",
        description:
          `\`${path}\` carries ${toplam} script tag(s) and none of them has a nonce; because the CSP uses ` +
          "`strict-dynamic`, none of them will execute. The page merely looks like it loads.",
        evidence: [httpEvidence(r.requestLine, `${r.responseLine} · script=${toplam} nonce=${nonceli}`)],
        remediation:
          "Bind the page to request time so a nonce can be emitted. To verify: on that page the script count " +
          "must equal the nonce count.",
      });
    }
    return findings;
  },
};
