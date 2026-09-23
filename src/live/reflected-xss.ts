import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A03 (live) — a reflected input probe (non-destructive).
 * A harmless unique marker is sent in the query; if it comes back in the
 * response WITHOUT HTML encoding, reflected XSS is flagged as possible. The payload does not execute.
 */

const MARKER = "nctrn__probe__7q1";
// a harmless marker that is noticeable if it gets encoded
const RAW = `${MARKER}<z>"'`;

export const liveReflectedXss: LiveRule = {
  id: "a03-live-reflected-input",
  title: "Live: reflected (unencoded) input — possible XSS",
  owasp: "A03:2021-Injection",
  severity: "medium",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    const q = encodeURIComponent(RAW);
    const paths = [`/?q=${q}`, `/search?q=${q}`];
    for (const path of paths) {
      const res = await ctx.probe(path);
      if (!res.ok || res.status !== 200) continue;
      const ct = res.headers["content-type"] ?? "";
      if (!/html/.test(ct)) continue;
      const body = res.bodySnippet;
      // is there a raw < > reflection (unencoded)
      const rawReflected = body.includes(`${MARKER}<z>`);
      const encodedReflected =
        body.includes(`${MARKER}&lt;z&gt;`) || body.includes(MARKER + "%3C");
      if (rawReflected && !encodedReflected) {
        findings.push({
          ruleId: this.id,
          title: "Input is reflected without HTML encoding",
          owasp: this.owasp,
          severity: "high",
          description:
            "A marker containing < and > was reflected into the response body unencoded. Reflected XSS is likely. (Non-destructive probe — verify by hand.)",
          evidence: [
            httpEvidence(
              res.requestLine,
              `HTTP ${res.status}\n…${body.slice(Math.max(0, body.indexOf(MARKER) - 20), body.indexOf(MARKER) + 40)}…`,
            ),
          ],
          remediation:
            "HTML-encode user input on output, rely on the framework's automatic escaping, avoid dangerouslySetInnerHTML, and add a CSP.",
        });
      } else if (rawReflected === false && body.includes(MARKER)) {
        // an encoded reflection = safe, no finding
      }
    }
    return findings;
  },
};
