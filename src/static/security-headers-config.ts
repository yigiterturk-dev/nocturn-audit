import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A05 — next.config güvenlik header'ları eksik.
 * CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy vb.
 */

const CONFIG_FILES = [
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "next.config.cjs",
];

interface HeaderCheck {
  name: string;
  re: RegExp;
  severity: "high" | "medium" | "low";
}

const REQUIRED: HeaderCheck[] = [
  { name: "Content-Security-Policy", re: /Content-Security-Policy/i, severity: "high" },
  { name: "X-Frame-Options", re: /X-Frame-Options/i, severity: "medium" },
  { name: "X-Content-Type-Options", re: /X-Content-Type-Options/i, severity: "medium" },
  { name: "Strict-Transport-Security", re: /Strict-Transport-Security/i, severity: "medium" },
  { name: "Referrer-Policy", re: /Referrer-Policy/i, severity: "low" },
];

export const securityHeadersConfig: StaticRule = {
  id: "a05-missing-security-headers",
  title: "next.config güvenlik header'ları eksik",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "static",
  run(ctx): Finding[] {
    // yalnızca Next.js projelerinde anlamlı
    if (ctx.project.stack.framework !== "next") return [];

    const configFile = CONFIG_FILES.find((f) => ctx.exists(f));
    if (!configFile) {
      return [
        {
          ruleId: this.id,
          title: "next.config bulunamadı — güvenlik header'ları tanımsız",
          owasp: this.owasp,
          severity: "medium",
          description:
            "Next.js projesi ama next.config dosyası yok; güvenlik header'ları (CSP, X-Frame-Options vb.) merkezi olarak tanımlanmamış olabilir.",
          evidence: [fileEvidence("next.config.js", 1, "(dosya yok)")],
          remediation:
            "next.config.js'e headers() fonksiyonu ekleyip CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy tanımlayın.",
        },
      ];
    }

    const content = ctx.read(configFile) ?? "";
    const hasHeadersFn = /headers\s*\(\s*\)|async\s+headers/.test(content);
    const missing = REQUIRED.filter((h) => !h.re.test(content));

    if (missing.length === 0) return [];

    const findings: Finding[] = [];
    for (const h of missing) {
      findings.push({
        ruleId: this.id,
        title: `Güvenlik header eksik: ${h.name}`,
        owasp: this.owasp,
        severity: h.severity,
        description: hasHeadersFn
          ? `next.config headers() tanımlı ama ${h.name} bulunamadı.`
          : `next.config'te headers() tanımı ve ${h.name} yok.`,
        evidence: [fileEvidence(configFile, 1, `${h.name} tanımlı değil`)],
        remediation: `next.config headers() içinde ${h.name} ekleyin. CSP için katı bir politika, X-Frame-Options: DENY/SAMEORIGIN, X-Content-Type-Options: nosniff önerilir.`,
      });
    }
    return findings;
  },
};
