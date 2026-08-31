import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A09 — missing security logging (informational).
 * No audit log or structured logging on auth and payment endpoints.
 */

const isSensitiveRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/").toLowerCase();
  return (
    (/(app\/.*\/route\.(ts|js))|(pages\/api\/)/.test(f)) &&
    /(login|signin|auth|payment|checkout|charge|webhook|admin|reset|register)/.test(f)
  );
};

const LOG_HINT =
  /(logger\.|auditLog|audit_log|console\.(log|info|warn|error)|logEvent|track\(|captureMessage|Sentry|pino|winston|logtail)/i;

export const auditLogging: StaticRule = {
  id: "a09-missing-audit-logging",
  title: "No security or audit logging on a sensitive endpoint",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "info",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!isSensitiveRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      if (LOG_HINT.test(content)) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "info",
        description:
          "A sensitive endpoint (authentication or payment) shows no logging at all. Audit logs are what make incident response and detection possible.",
        evidence: [fileEvidence(file, 1, file.replace(/\\/g, "/"))],
        remediation:
          "Record successful and failed auth and payment events (user, IP, timestamp, outcome) with a structured logger, and alert on anomalies.",
      });
    }
    return findings;
  },
};
