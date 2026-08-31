import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A07 (live) — login rate limiting and user enumeration (a light probe).
 * Non-destructive: a couple of invalid login attempts. It does NOT brute force (≤3 requests).
 * Only: (a) does it never return a rate limit, (b) does the response leak "no such user" vs "wrong password".
 */

const LOGIN_PATHS = ["/api/auth/login", "/api/login", "/api/auth/callback/credentials"];

export const liveUserEnumeration: LiveRule = {
  id: "a07-live-login-hardening",
  title: "Live: login rate limiting and user enumeration",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "medium",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of LOGIN_PATHS) {
      // first, does the endpoint exist (one request)
      const probe1 = await ctx.probe(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "nocturn_probe_absent@example.invalid",
          password: "x",
        }),
      });
      if (!probe1.ok) continue;
      // skip when the endpoint is absent (404/405)
      if ([404, 405].includes(probe1.status)) continue;

      // second attempt (does a rate limit trigger) — two requests in total, no brute force
      const probe2 = await ctx.probe(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "nocturn_probe_absent2@example.invalid",
          password: "x",
        }),
      });

      // NOT MEASURED ≠ NOT PRESENT. In most projects the login endpoint carries an
      // origin/CSRF gate BEFORE the brake: because the probe sends no Origin header
      // it gets a 403 and never reaches the rate limiter. That happened in one
      // project — the code had an 8-per-10-minutes limit while the probe said "no
      // rate-limit signal". A measurement that hits a gate says nothing about what
      const kapiyaTosladi = [401, 403].includes(probe1.status) && !probe1.headers["retry-after"];
      const isRedactedSource =
        /invalid origin|geçersiz istek kaynağı|csrf|forbidden origin|cross[- ]origin/i.test(
          probe1.bodySnippet ?? "",
        );
      if (kapiyaTosladi && isRedactedSource) {
        findings.push({
          ruleId: this.id,
          title: `Login throttling COULD NOT BE MEASURED (origin gate): ${path}`,
          owasp: this.owasp,
          severity: "info",
          confidence: "certain",
          description:
            "The login endpoint rejected the probe with an origin/CSRF check BEFORE the rate limiter (403). " +
            "That does NOT show throttling is missing — the measurement never reached it. The origin gate is itself good " +
            "protection. To verify throttling, either find the rate-limit call in the code or give the probe the correct Origin header.",
          evidence: [
            httpEvidence(probe1.requestLine, `HTTP ${probe1.status} — origin/CSRF reddi`),
          ],
          remediation:
            "This is a measurement gap, not a finding. To close it, statically confirm the rate-limit call on the login route.",
        });
        break;
      }

      const hasRateLimitHeader =
        probe1.headers["ratelimit-limit"] ||
        probe1.headers["x-ratelimit-limit"] ||
        probe1.headers["retry-after"] ||
        probe2.status === 429;

      if (!hasRateLimitHeader) {
        findings.push({
          ruleId: this.id,
          title: `No rate-limit signal on the login endpoint: ${path}`,
          owasp: this.owasp,
          severity: "medium",
          description:
            "Repeated attempts against the login endpoint produced no rate-limit header and no 429. Brute-force protection could not be confirmed. (Two-request probe — not conclusive.)",
          evidence: [
            httpEvidence(
              probe1.requestLine,
              `HTTP ${probe1.status} (rate-limit header yok)`,
            ),
          ],
          remediation:
            "Add IP and account based rate limiting to login, return a generic message on failure, and respond 429 with Retry-After.",
        });
      }

      // stop at the first real login endpoint found
      break;
    }
    return findings;
  },
};
