import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — weak cryptography: md5/sha1 for passwords, a hardcoded JWT secret.
 */

const WEAK_HASH =
  /createHash\(\s*['"](md5|sha1)['"]\s*\)|\b(md5|sha1)\s*\(/i;
const PASSWORD_CTX = /(password|passwd|pwd|parola|şifre|sifre|secret)/i;
const HARDCODED_JWT =
  /(jwt|token)[^\n]{0,30}(secret|sign)[^\n]{0,10}[:=]\s*["'`][^"'`]{4,}["'`]/i;
const JWT_ENV = /(process\.env|import\.meta\.env)/;

export const weakHash: StaticRule = {
  id: "a02-weak-hash-or-jwt-secret",
  title: "Weak hash (md5/sha1) or hardcoded JWT secret",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  // A weak hash (md5/sha1) for a password or token → deterministic.
  confidence: "certain",
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];

        if (WEAK_HASH.test(raw)) {
          const around = lines.slice(Math.max(0, i - 2), i + 3).join("\n");
          if (PASSWORD_CTX.test(around)) {
            findings.push({
              ruleId: this.id,
              title: "Weak hash used for passwords (md5/sha1)",
              owasp: this.owasp,
              severity: "high",
              description:
                "md5 or sha1 is used in a password or secret context. These algorithms are fast and broken, and are unsuitable for storing passwords.",
              evidence: [fileEvidence(file, i + 1, raw)],
              remediation:
                "Use bcrypt, scrypt or argon2 for passwords (salt plus a work factor), and remove md5/sha1 from the password path.",
            });
          }
        }

        if (HARDCODED_JWT.test(raw) && !JWT_ENV.test(raw)) {
          findings.push({
            ruleId: this.id,
            title: "Sabit (hardcoded) JWT secret",
            owasp: this.owasp,
            severity: "high",
            description:
              "The JWT signing secret appears to be hardcoded. Once a fixed secret leaks with the repository, tokens can be forged.",
            evidence: [fileEvidence(file, i + 1, raw.replace(/["'`][^"'`]{4,}["'`]/, '"…redacted…"'))],
            remediation:
              "Read the JWT secret from an environment variable, use a strong random value, and plan for rotation.",
          });
        }
      }
    }
    return findings;
  },
};
