import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A05 (live) — dangerous HTTP methods.
 *
 * A TRACE request that is not rejected can be abused for cross-site tracing
 * (XST). OPTIONS revealing a broad Allow list is informational.
 */

export const liveHttpMethods: LiveRule = {
  id: "a05-live-http-methods",
  title: "Live: dangerous HTTP methods enabled",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "low",
  kind: "live",
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];

    const trace = await ctx.probe("/", { method: "TRACE" });
    if (trace.ok && trace.status >= 200 && trace.status < 300) {
      findings.push({
        ruleId: this.id,
        title: "TRACE method is enabled",
        owasp: this.owasp,
        severity: "medium",
        description:
          "The server answers TRACE with a 2xx. TRACE can be abused for cross-site tracing (XST) and reflects the request back.",
        evidence: [httpEvidence(trace.requestLine, trace.responseLine)],
        remediation: "Disable TRACE (and TRACK) at the server or reverse proxy.",
      });
    }

    const options = await ctx.probe("/", { method: "OPTIONS" });
    if (options.ok && options.status >= 200 && options.status < 300) {
      const allow = options.headers["allow"] ?? options.headers["access-control-allow-methods"];
      if (allow && /\b(TRACE|TRACK|PUT|DELETE)\b/i.test(allow)) {
        findings.push({
          ruleId: this.id,
          title: "Broad HTTP method allow-list",
          owasp: this.owasp,
          severity: "low",
          description: `The server advertises ${allow}. Unused write methods widen the attack surface.`,
          evidence: [httpEvidence(options.requestLine, options.responseLine)],
          remediation: "Restrict the Allow header to the methods the endpoint actually needs.",
        });
      }
    }

    return findings;
  },
};
