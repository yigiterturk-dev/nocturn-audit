import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A07 — weak or wrong JWT verification:
 * - alg "none"
 * - decoding without verifying the signature and then trusting it (authorisation via jwt.decode)
 * - no algorithm restriction in verify
 */

const ALG_NONE = /alg\s*[:=]\s*["']none["']|algorithm[s]?\s*[:=][^\n]*["']none["']/i;
const DECODE_ONLY = /jwt\.decode\s*\(|jwtDecode\s*\(|decodeJwt\s*\(/;
const VERIFY = /jwt\.verify\s*\(|jose|jwtVerify/;
const IGNORE_EXP = /ignoreExpiration\s*:\s*true/;
// Algorithm confusion: a symmetric (HS*) and an asymmetric (RS/ES/PS*) algorithm in the same list.
// An attacker can sign a forged token using the public key as the HMAC secret.
const ALG_CONFUSION =
  /algorithms?\s*[:=]\s*\[[^\]]*\bHS\d{3}\b[^\]]*\b(?:RS|ES|PS)\d{3}\b|algorithms?\s*[:=]\s*\[[^\]]*\b(?:RS|ES|PS)\d{3}\b[^\]]*\bHS\d{3}\b/i;

export const jwtWeakVerification: StaticRule = {
  id: "a07-jwt-weak-verification",
  title: "Weak or missing JWT verification",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  // alg:none / decode-only yetkilendirme → deterministik.
  confidence: "certain",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      const fileHasVerify = VERIFY.test(content);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];

        if (ALG_NONE.test(raw)) {
          findings.push({
            ruleId: this.id,
            title: 'JWT "none" algorithm',
            owasp: this.owasp,
            severity: "critical",
            description:
              'alg "none" is used or accepted for JWTs. Accepting unsigned tokens allows complete identity forgery.',
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation:
              'Reject alg "none" and pin the algorithm explicitly in the verify call (e.g. ["HS256"] or ["RS256"]).',
          });
        }

        if (ALG_CONFUSION.test(raw)) {
          findings.push({
            ruleId: this.id,
            title: "JWT algorithm confusion (HS accepted alongside RS/ES)",
            owasp: this.owasp,
            severity: "high",
            cwe: "CWE-347",
            description:
              "JWT verification accepts a symmetric (HS256) and an asymmetric (RS256/ES256) algorithm in the same list. An attacker can sign a token with the server's public key used as the HMAC secret (algorithm confusion).",
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation:
              "Pin one algorithm family in the verify call (RS256 only, or HS256 only). Never allow symmetric and asymmetric algorithms in the same allowlist.",
          });
        }

        if (IGNORE_EXP.test(raw)) {
          findings.push({
            ruleId: this.id,
            title: "JWT expiry check disabled (ignoreExpiration)",
            owasp: this.owasp,
            severity: "medium",
            description:
              "JWT verification sets ignoreExpiration:true, so expired tokens are accepted.",
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation: "Remove ignoreExpiration and keep the exp check enabled.",
          });
        }

        // authorisation from a decode-only result: no verify in the file, and the decoded claims drive auth or role
        // ⚠️ DİL AYRIMI (gerçek vaka, 2026-09-23 — dış-precision deneyi, 1 FP):
        // Python'da PyJWT'nin `jwt.decode(token, key, algorithms=[...])` çağrısı
        // imzayı DOĞRULAR (JS jsonwebtoken'un decode-only'sinden farklı!). .py
        // dosyasında anahtar + algorithms= ile çağrılan decode zayif değildir.
        const around = lines.slice(i, i + 5).join("\n");
        const isPyJwtDecode =
          /\.py$/.test(file) && /algorithms\s*=/.test(around);
        if (DECODE_ONLY.test(raw) && !fileHasVerify && !isPyJwtDecode) {
          if (/(role|userId|user_id|isAdmin|admin|sub|permission|auth)/i.test(around)) {
            findings.push({
              ruleId: this.id,
              title: "JWT decoded without signature verification, then trusted",
              owasp: this.owasp,
              severity: "high",
              description:
                "The token is only decoded (never signature-verified) and its claims (role/user/permission) drive authorisation. An attacker can craft any payload.",
              evidence: [fileEvidence(file, i + 1, raw)],
              remediation:
                "Verify the signature and algorithm with jwt.verify / jwtVerify before any authorisation decision; never trust a decode-only result.",
            });
          }
        }
      }
    }
    return findings;
  },
};
