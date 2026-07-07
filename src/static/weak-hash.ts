import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — Zayıf kriptografi: md5/sha1 ile parola, sabit JWT secret.
 */

const WEAK_HASH =
  /createHash\(\s*['"](md5|sha1)['"]\s*\)|\b(md5|sha1)\s*\(/i;
const PASSWORD_CTX = /(password|passwd|pwd|parola|şifre|sifre|secret)/i;
const HARDCODED_JWT =
  /(jwt|token)[^\n]{0,30}(secret|sign)[^\n]{0,10}[:=]\s*["'`][^"'`]{4,}["'`]/i;
const JWT_ENV = /(process\.env|import\.meta\.env)/;

export const weakHash: StaticRule = {
  id: "a02-weak-hash-or-jwt-secret",
  title: "Zayıf hash (md5/sha1) veya sabit JWT secret",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  kind: "static",
  // Zayıf hash (md5/sha1) parola/token için → deterministik.
  confidence: "kesin",
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
              title: "Parola için zayıf hash (md5/sha1)",
              owasp: this.owasp,
              severity: "high",
              description:
                "Parola/sır bağlamında md5 ya da sha1 kullanılıyor. Bu algoritmalar hızlı ve kırılabilir; parola saklamak için uygun değil.",
              evidence: [fileEvidence(file, i + 1, raw)],
              remediation:
                "Parolalar için bcrypt/scrypt/argon2 kullanın (tuz + iş faktörü). md5/sha1'i parola akışından kaldırın.",
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
              "JWT imza secret'ı koda gömülmüş görünüyor. Sabit secret depoya sızarsa token sahteciliği mümkün olur.",
            evidence: [fileEvidence(file, i + 1, raw.replace(/["'`][^"'`]{4,}["'`]/, '"…redacted…"'))],
            remediation:
              "JWT secret'ı ortam değişkeninden okuyun, güçlü rastgele bir değer kullanın ve rotasyon planlayın.",
          });
        }
      }
    }
    return findings;
  },
};
