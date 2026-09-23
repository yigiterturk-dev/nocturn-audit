import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A05 — next.config is missing security headers.
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
  title: "next.config is missing security headers",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    // only meaningful in Next.js projects
    if (ctx.project.stack.framework !== "next") return [];

    const configFile = CONFIG_FILES.find((f) => ctx.exists(f));
    if (!configFile) {
      return [
        {
          ruleId: this.id,
          title: "No next.config found — security headers are undefined",
          owasp: this.owasp,
          severity: "medium",
          description:
            "This is a Next.js project with no next.config file, so security headers (CSP, X-Frame-Options and friends) may not be defined centrally anywhere.",
          evidence: [fileEvidence("next.config.js", 1, "(dosya yok)")],
          remediation:
            "Add a headers() function to next.config.js declaring CSP, X-Frame-Options, X-Content-Type-Options, HSTS and Referrer-Policy.",
        },
      ];
    }

    // Headers are NOT looked for in next.config alone.
    //
    // In Next 13+ projects security headers are usually emitted in middleware
    // (`proxy.ts` in Next 16) — especially CSP, because it needs a per-request
    // nonce and static config cannot do that. Because the rule looked only at the
    // config, it reported "no CSP" for projects whose CSP was complete.
    const HEADER_KAYNAKLARI = [
      configFile,
      "middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js",
      "proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js",
      "vercel.json", "netlify.toml", "public/_headers",
    ];
    const birlesik = HEADER_KAYNAKLARI.map((f) => ctx.read(f) ?? "").join("\n");
    const content = ctx.read(configFile) ?? "";
    const hasHeadersFn = /headers\s*\(\s*\)|async\s+headers|\.headers\.set\s*\(/.test(birlesik);
    const missing = REQUIRED.filter((h) => !h.re.test(birlesik));

    if (missing.length === 0) return [];

    const findings: Finding[] = [];
    for (const h of missing) {
      findings.push({
        ruleId: this.id,
        title: `Missing security header: ${h.name}`,
        owasp: this.owasp,
        severity: h.severity,
        description: hasHeadersFn
          ? `Headers are declared somewhere, but ${h.name} appears in none of them (next.config, middleware/proxy, vercel.json, _headers).`
          : `${h.name} is not declared in any header source (next.config, middleware/proxy, vercel.json, _headers).`,
        evidence: [fileEvidence(configFile, 1, `${h.name} not declared`)],
        remediation: `Add ${h.name} inside next.config headers(). Use a strict CSP, X-Frame-Options: DENY or SAMEORIGIN, and X-Content-Type-Options: nosniff.`,
      });
    }
    return findings;
  },
};
