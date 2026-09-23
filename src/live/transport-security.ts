import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A02 (live) — missing HSTS and missing cookie Secure/HttpOnly/SameSite.
 */

export const liveTransportSecurity: LiveRule = {
  id: "a02-live-transport-and-cookies",
  title: "Live: HSTS and cookie security flags",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "medium",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    const res = await ctx.probe("/");
    if (!res.ok) return [];
    const findings: Finding[] = [];

    const isHttps = res.url.startsWith("https://");
    if (isHttps && !res.headers["strict-transport-security"]) {
      findings.push({
        ruleId: this.id,
        title: "HSTS (Strict-Transport-Security) missing",
        owasp: this.owasp,
        severity: "medium",
        description:
          "The site is served over HTTPS but sends no Strict-Transport-Security header, leaving it open to SSL stripping and downgrade attacks.",
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
          title: `Missing cookie flag: ${missing.join(", ")}`,
          owasp: this.owasp,
          severity: missing.includes("HttpOnly") ? "medium" : "low",
          description: `The Set-Cookie response is missing ${missing.join(", ")}. Session cookies are more exposed to XSS, MITM and CSRF.`,
          evidence: [
            httpEvidence(res.requestLine, `set-cookie: ${setCookie.slice(0, 200)}`),
          ],
          remediation:
            "Add HttpOnly, Secure (over HTTPS) and SameSite=Lax/Strict to session cookies.",
        });
      }
    }

    return findings;
  },
};
