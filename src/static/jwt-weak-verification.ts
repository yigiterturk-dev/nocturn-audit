import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A07 — JWT doğrulama zayıf/yanlış:
 * - alg "none"
 * - imza doğrulamadan decode edip güvenmek (jwt.decode ile yetki)
 * - verify'de algoritma kısıtı yok
 */

const ALG_NONE = /alg\s*[:=]\s*["']none["']|algorithm[s]?\s*[:=][^\n]*["']none["']/i;
const DECODE_ONLY = /jwt\.decode\s*\(|jwtDecode\s*\(|decodeJwt\s*\(/;
const VERIFY = /jwt\.verify\s*\(|jose|jwtVerify/;
const IGNORE_EXP = /ignoreExpiration\s*:\s*true/;
// Algoritma karışıklığı: aynı algorithms listesinde hem simetrik (HS*) hem asimetrik (RS/ES/PS*).
// Saldırgan public key'i HMAC secret'ı olarak kullanıp token sahteleyebilir.
const ALG_CONFUSION =
  /algorithms?\s*[:=]\s*\[[^\]]*\bHS\d{3}\b[^\]]*\b(?:RS|ES|PS)\d{3}\b|algorithms?\s*[:=]\s*\[[^\]]*\b(?:RS|ES|PS)\d{3}\b[^\]]*\bHS\d{3}\b/i;

export const jwtWeakVerification: StaticRule = {
  id: "a07-jwt-weak-verification",
  title: "Zayıf/eksik JWT doğrulaması",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "high",
  kind: "static",
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
            title: 'JWT "none" algoritması',
            owasp: this.owasp,
            severity: "critical",
            description:
              'JWT için alg "none" kullanılıyor/kabul ediliyor. İmzasız token kabulü tam kimlik sahteciliğine yol açar.',
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation:
              'alg "none"u yasaklayın; verify çağrısında algoritmayı açıkça (ör. ["HS256"]/["RS256"]) sabitleyin.',
          });
        }

        if (ALG_CONFUSION.test(raw)) {
          findings.push({
            ruleId: this.id,
            title: "JWT algoritma karışıklığı (HS + RS/ES birlikte)",
            owasp: this.owasp,
            severity: "high",
            cwe: "CWE-347",
            description:
              "JWT doğrulaması aynı listede hem simetrik (HS256) hem asimetrik (RS256/ES256) algoritmayı kabul ediyor. Saldırgan, sunucunun public key'ini HMAC secret'ı olarak kullanıp geçerli imza üretebilir (algorithm confusion).",
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation:
              "verify çağrısında tek bir algoritma ailesini sabitleyin (yalnızca RS256 ya da yalnızca HS256). Simetrik ve asimetrik algoritmaları asla aynı allowlist'te tutmayın.",
          });
        }

        if (IGNORE_EXP.test(raw)) {
          findings.push({
            ruleId: this.id,
            title: "JWT süre kontrolü kapalı (ignoreExpiration)",
            owasp: this.owasp,
            severity: "medium",
            description:
              "JWT doğrulamasında ignoreExpiration:true; süresi dolmuş token'lar kabul ediliyor.",
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation: "ignoreExpiration'ı kaldırın; exp kontrolünü açık tutun.",
          });
        }

        // decode-only ile yetki: aynı dosyada verify yoksa ve decode sonucu auth/rol için kullanılıyorsa
        if (DECODE_ONLY.test(raw) && !fileHasVerify) {
          const around = lines.slice(i, i + 5).join("\n");
          if (/(role|userId|user_id|isAdmin|admin|sub|permission|auth)/i.test(around)) {
            findings.push({
              ruleId: this.id,
              title: "İmza doğrulamadan JWT decode edip güvenme",
              owasp: this.owasp,
              severity: "high",
              description:
                "Token yalnızca decode ediliyor (imza doğrulaması yok) ve içeriği (rol/kullanıcı/izin) yetki için kullanılıyor. Saldırgan payload'ı istediği gibi üretebilir.",
              evidence: [fileEvidence(file, i + 1, raw)],
              remediation:
                "Yetki kararından önce jwt.verify / jwtVerify ile imzayı ve algoritmayı doğrulayın; decode-only sonucuna güvenmeyin.",
            });
          }
        }
      }
    }
    return findings;
  },
};
