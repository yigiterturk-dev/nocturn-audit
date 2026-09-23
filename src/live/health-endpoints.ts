import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A09 (live) — do the health endpoints actually answer?
 *
 * Seeing that they are defined is not enough. A health endpoint can return 500
 * for days without anyone hearing: the monitor goes down, and with no alert
 * target nobody sees that either. A single request exposes it.
 */
const PATHS = [
  "/api/health/live",
  "/api/health/ready",
  "/api/health",
  "/api/healthz",
  "/healthz",
  "/health",
  "/api/status",
];

export const liveHealthEndpoints: LiveRule = {
  id: "int-live-health-endpoints",
  title: "Health endpoint returns an error",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "high",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  confidence: "certain",
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const path of PATHS) {
      const r = await ctx.probe(path);
      // A missing endpoint (404) is not a finding — not every project needs one.
      if (r.status === 404 || r.status === 0) continue;
      if (r.status >= 200 && r.status < 400) continue;
      // 503 means "not ready" and may be deliberate; the rest of the 5xx range is a failure.
      const bilincli = r.status === 503 && r.bodySnippet.trim().length > 0;
      if (bilincli) continue;

      findings.push({
        ruleId: "int-live-health-endpoints",
        title: "Health endpoint returns an error",
        owasp: "A09:2021-Security Logging & Monitoring Failures",
        severity: "high",
        confidence: "certain",
        description:
          `\`${path}\` returned HTTP ${r.status}${r.bodySnippet.trim() ? "" : " with an empty body"}. ` +
          "A health endpoint is the one place that must answer even when everything else is broken; when it is broken itself, " +
          "every monitor built on top of it fails silently.",
        evidence: [httpEvidence(r.requestLine, r.responseLine)],
        remediation:
          "Find the error inside the endpoint (usually one broken or missing record). It should validate " +
          "the shape so a single bad record cannot take it down.",
      });
    }
    return findings;
  },
};
