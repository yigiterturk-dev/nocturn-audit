import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A09 — Güvenlik loglama eksikliği (bilgilendirici).
 * Auth/ödeme uçlarında audit log / structured logging izi yok.
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
  title: "Hassas uçta güvenlik/audit loglaması yok",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "info",
  kind: "static",
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
          "Kimlik doğrulama/ödeme gibi hassas bir uçta herhangi bir loglama izi görünmüyor. Olay müdahalesi ve tespit için audit log önerilir.",
        evidence: [fileEvidence(file, 1, file.replace(/\\/g, "/"))],
        remediation:
          "Başarılı/başarısız auth ve ödeme olaylarını (kullanıcı, IP, zaman, sonuç) yapısal bir logger ile kaydedin; anomali alarmı kurun.",
      });
    }
    return findings;
  },
};
