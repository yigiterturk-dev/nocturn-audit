import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A09 — security.txt yok (bilgilendirme).
 *
 * Under RFC 9116, `/.well-known/security.txt` provides a contact channel for
 * vulnerability disclosure. Reminds you (info) when a web-facing project has none.
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
  title: "No security.txt (RFC 9116)",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "info",
  cwe: "CWE-200",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx: StaticContext): Finding[] {
    // Web-facing projects only (next/vite).
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
          "The project has no /.well-known/security.txt. That file declares a contact channel so security researchers can disclose issues responsibly (RFC 9116).",
        evidence: [fileEvidence("public/.well-known/security.txt", 1, "(dosya yok)")],
        remediation:
          "Add public/.well-known/security.txt with Contact and Expires fields, and preferably Encryption and Policy too.",
        remediationCode:
          "Contact: mailto:security@example.com\n" +
          "Expires: 2027-01-01T00:00:00.000Z\n" +
          "Preferred-Languages: tr, en",
      },
    ];
  },
};
