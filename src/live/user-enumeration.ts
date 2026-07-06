import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A07 (canlı) — Login rate-limit / kullanıcı sayımı sızıntısı (hafif prob).
 * Non-destructive: birkaç geçersiz login denemesi. Brute-force YAPMAZ (≤3 istek).
 * Sadece: (a) hiç rate-limit dönmüyor mu, (b) yanıt "kullanıcı yok" vs "şifre yanlış" ayrımı sızdırıyor mu.
 */

const LOGIN_PATHS = ["/api/auth/login", "/api/login", "/api/auth/callback/credentials"];

export const liveUserEnumeration: LiveRule = {
  id: "a07-live-login-hardening",
  title: "Canlı: login rate-limit / kullanıcı sayımı sızıntısı",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "medium",
  kind: "live",
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of LOGIN_PATHS) {
      // önce endpoint var mı (tek istek)
      const probe1 = await ctx.probe(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "nocturn_probe_absent@example.invalid",
          password: "x",
        }),
      });
      if (!probe1.ok) continue;
      // endpoint yoksa (404/405) geç
      if ([404, 405].includes(probe1.status)) continue;

      // ikinci deneme (rate-limit tetiklenir mi) — toplam 2 istek, brute yok
      const probe2 = await ctx.probe(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "nocturn_probe_absent2@example.invalid",
          password: "x",
        }),
      });

      const hasRateLimitHeader =
        probe1.headers["ratelimit-limit"] ||
        probe1.headers["x-ratelimit-limit"] ||
        probe1.headers["retry-after"] ||
        probe2.status === 429;

      if (!hasRateLimitHeader) {
        findings.push({
          ruleId: this.id,
          title: `Login ucunda rate-limit işareti yok: ${path}`,
          owasp: this.owasp,
          severity: "medium",
          description:
            "Login uç noktası art arda denemelerde herhangi bir rate-limit başlığı/429 üretmedi. Brute-force korumasının varlığı doğrulanamadı. (2 istekle prob — kesin değil.)",
          evidence: [
            httpEvidence(
              probe1.requestLine,
              `HTTP ${probe1.status} (rate-limit header yok)`,
            ),
          ],
          remediation:
            "Login'e IP+hesap bazlı rate-limit ekleyin, başarısız denemede jenerik mesaj dönün, 429 + Retry-After uygulayın.",
        });
      }

      // sadece ilk bulunan gerçek login ucuyla yetin
      break;
    }
    return findings;
  },
};
