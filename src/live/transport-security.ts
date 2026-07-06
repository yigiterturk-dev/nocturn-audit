import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A02 (canlı) — HSTS eksik + cookie Secure/HttpOnly/SameSite eksik.
 */

export const liveTransportSecurity: LiveRule = {
  id: "a02-live-transport-and-cookies",
  title: "Canlı: HSTS / cookie güvenlik bayrakları",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "medium",
  kind: "live",
  async run(ctx): Promise<Finding[]> {
    const res = await ctx.probe("/");
    if (!res.ok) return [];
    const findings: Finding[] = [];

    const isHttps = res.url.startsWith("https://");
    if (isHttps && !res.headers["strict-transport-security"]) {
      findings.push({
        ruleId: this.id,
        title: "HSTS (Strict-Transport-Security) eksik",
        owasp: this.owasp,
        severity: "medium",
        description:
          "HTTPS sunuluyor ama Strict-Transport-Security başlığı yok. SSL-stripping / downgrade saldırısına açık.",
        evidence: [httpEvidence(res.requestLine, res.responseLine)],
        remediation:
          "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload ekleyin.",
      });
    }

    const setCookie = res.headers["set-cookie"];
    if (setCookie) {
      const lower = setCookie.toLowerCase();
      const missing: string[] = [];
      if (!/httponly/.test(lower)) missing.push("HttpOnly");
      if (isHttps && !/secure/.test(lower)) missing.push("Secure");
      if (!/samesite/.test(lower)) missing.push("SameSite");
      if (missing.length) {
        findings.push({
          ruleId: this.id,
          title: `Cookie bayrağı eksik: ${missing.join(", ")}`,
          owasp: this.owasp,
          severity: missing.includes("HttpOnly") ? "medium" : "low",
          description: `Set-Cookie yanıtında ${missing.join(", ")} bayrağı yok. Oturum çerezleri XSS/MITM/CSRF'e daha açık.`,
          evidence: [
            httpEvidence(res.requestLine, `set-cookie: ${setCookie.slice(0, 200)}`),
          ],
          remediation:
            "Oturum çerezlerine HttpOnly, Secure (HTTPS) ve SameSite=Lax/Strict bayraklarını ekleyin.",
        });
      }
    }

    return findings;
  },
};
