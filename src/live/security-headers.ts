import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

/**
 * A05 (canlı) — Yanıt güvenlik header'ları taraması.
 * Non-destructive: tek GET /.
 */

interface HeaderCheck {
  header: string;
  severity: Severity;
  note: string;
  fix: string;
}

const CHECKS: HeaderCheck[] = [
  {
    header: "content-security-policy",
    severity: "medium",
    note: "CSP yok — XSS/veri sızıntısına karşı katman eksik.",
    fix: "Katı bir Content-Security-Policy tanımlayın.",
  },
  {
    header: "x-frame-options",
    severity: "medium",
    note: "X-Frame-Options yok — clickjacking mümkün (CSP frame-ancestors de yoksa).",
    fix: "X-Frame-Options: DENY/SAMEORIGIN veya CSP frame-ancestors ekleyin.",
  },
  {
    header: "x-content-type-options",
    severity: "low",
    note: "X-Content-Type-Options yok — MIME sniffing riski.",
    fix: "X-Content-Type-Options: nosniff ekleyin.",
  },
  {
    header: "referrer-policy",
    severity: "low",
    note: "Referrer-Policy yok — referer sızıntısı.",
    fix: "Referrer-Policy: strict-origin-when-cross-origin ekleyin.",
  },
];

export const liveSecurityHeaders: LiveRule = {
  id: "a05-live-security-headers",
  title: "Canlı: eksik güvenlik header'ları",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "live",
  async run(ctx): Promise<Finding[]> {
    const res = await ctx.probe("/");
    if (!res.ok) return [];
    const findings: Finding[] = [];
    const csp = res.headers["content-security-policy"];
    for (const check of CHECKS) {
      const present = res.headers[check.header];
      // CSP frame-ancestors X-Frame-Options'ı karşılayabilir
      if (
        check.header === "x-frame-options" &&
        csp &&
        /frame-ancestors/i.test(csp)
      )
        continue;
      if (present) continue;
      findings.push({
        ruleId: this.id,
        title: `Eksik header: ${check.header}`,
        owasp: this.owasp,
        severity: check.severity,
        description: check.note,
        evidence: [httpEvidence(res.requestLine, res.responseLine)],
        remediation: check.fix,
      });
    }
    return findings;
  },
};
