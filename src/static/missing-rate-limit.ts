import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — no rate limiting on a sensitive flow (login/otp/payment/register/reset).
 * Brute-force and abuse protection is missing.
 */

const SENSITIVE_PATH =
  /(login|signin|sign-in|otp|verify|register|signup|sign-up|reset-?password|forgot|payment|checkout|charge|pay|tahsilat)/i;

const RATELIMIT_HINT =
  /(ratelimit|rate-limit|rateLimit|Ratelimit|upstash\/ratelimit|@upstash\/ratelimit|throttle|limiter|express-rate-limit|slowDown|bottleneck|nextRateLimit|leaky|tokenBucket)/i;

const isApiRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /(^|\/)app\/.*\/route\.(ts|js)$/.test(f) ||
    /(^|\/)pages\/api\/.*\.(ts|js)$/.test(f) ||
    /(^|\/)app\/.*actions?\.(ts|js)$/.test(f)
  );
};

export const missingRateLimit: StaticRule = {
  id: "a04-missing-rate-limit",
  title: "No rate limiting or brute-force protection on a sensitive endpoint",
  owasp: "A04:2021-Insecure Design",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // is there any rate-limit infrastructure anywhere in the project
    const globalRateLimit = ctx.grep(RATELIMIT_HINT).length > 0;

    for (const file of ctx.files) {
      if (!isApiRoute(file)) continue;
      const f = file.replace(/\\/g, "/");
      if (!SENSITIVE_PATH.test(f)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      if (RATELIMIT_HINT.test(content)) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: globalRateLimit ? "low" : "medium",
        description: globalRateLimit
          ? `No rate limiting is visible on this sensitive endpoint (${f}). The project does have rate-limit infrastructure, but it could not be confirmed on this route.`
          : `This sensitive flow (${f}) has no rate limiting or throttling, and the project has no rate-limit infrastructure at all. It is open to brute force and abuse.`,
        evidence: [fileEvidence(file, 1, f)],
        remediation:
          "Add IP and identity based rate limiting to login, OTP and payment endpoints (e.g. @upstash/ratelimit), cap failed attempts, and add a CAPTCHA or delay if needed.",
      });
    }
    return findings;
  },
};
