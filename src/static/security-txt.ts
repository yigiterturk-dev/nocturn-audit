import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A09 — security.txt yok (bilgilendirme).
 *
 * RFC 9116'ya göre `/.well-known/security.txt`, güvenlik açığı bildirimi için iletişim
 * kanalı sağlar. Web-facing projelerde yoksa (info) hatırlatır.
 */

const CANDIDATES = [
  "public/.well-known/security.txt",
  "public/security.txt",
  ".well-known/security.txt",
  "static/.well-known/security.txt",
  "app/.well-known/security.txt/route.ts",
  "app/.well-known/security.txt/route.js",
];

export const securityTxt: StaticRule = {
  id: "a09-security-txt-missing",
  title: "security.txt (RFC 9116) tanımlı değil",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "info",
  cwe: "CWE-200",
  kind: "static",
  run(ctx: StaticContext): Finding[] {
    // Yalnızca web-facing projeler (next/vite).
    const fw = ctx.project.stack.framework;
    if (fw !== "next" && fw !== "vite") return [];

    if (CANDIDATES.some((p) => ctx.exists(p))) return [];

    return [
      {
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "info",
        cwe: this.cwe,
        description:
          "Projede /.well-known/security.txt bulunamadı. Bu dosya, güvenlik araştırmacılarının açıkları sorumlu şekilde bildirebilmesi için bir iletişim kanalı tanımlar (RFC 9116).",
        evidence: [fileEvidence("public/.well-known/security.txt", 1, "(dosya yok)")],
        remediation:
          "public/.well-known/security.txt ekleyin: Contact, Expires ve tercihen Encryption/Policy alanlarını doldurun.",
        remediationCode:
          "Contact: mailto:security@example.com\n" +
          "Expires: 2027-01-01T00:00:00.000Z\n" +
          "Preferred-Languages: tr, en",
      },
    ];
  },
};
