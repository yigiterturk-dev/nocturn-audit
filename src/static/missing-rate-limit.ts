import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — Hassas akışta (login/otp/ödeme/register/reset) rate-limit yok.
 * Brute-force / kötüye kullanım koruması eksik.
 */

const SENSITIVE_PATH =
  /(login|signin|sign-in|otp|verify|register|signup|sign-up|reset-?password|forgot|payment|checkout|charge|pay|tahsilat)/i;

const RATELIMIT_HINT =
  /(ratelimit|rate-limit|rateLimit|Ratelimit|upstash\/ratelimit|@upstash\/ratelimit|throttle|limiter|express-rate-limit|slowDown|bottleneck|nextRateLimit|leaky|tokenBucket)/i;

const isApiRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /(^|\/)app\/.*\/route\.(ts|js)$/.test(f) ||
    /(^|\/)pages\/api\/.*\.(ts|js)$/.test(f) ||
    /(^|\/)app\/.*actions?\.(ts|js)$/.test(f)
  );
};

export const missingRateLimit: StaticRule = {
  id: "a04-missing-rate-limit",
  title: "Hassas uçta rate-limit / brute-force koruması yok",
  owasp: "A04:2021-Insecure Design",
  severity: "medium",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // proje genelinde herhangi bir rate-limit altyapısı var mı
    const globalRateLimit = ctx.grep(RATELIMIT_HINT).length > 0;

    for (const file of ctx.files) {
      if (!isApiRoute(file)) continue;
      const f = file.replace(/\\/g, "/");
      if (!SENSITIVE_PATH.test(f)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      if (RATELIMIT_HINT.test(content)) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: globalRateLimit ? "low" : "medium",
        description: globalRateLimit
          ? `Bu hassas uçta (${f}) doğrudan rate-limit görünmüyor. Projede rate-limit altyapısı var ama bu route'a uygulandığı doğrulanamadı.`
          : `Hassas akış (${f}) rate-limit / throttle içermiyor ve projede rate-limit altyapısı da bulunamadı. Brute-force ve kötüye kullanıma açık.`,
        evidence: [fileEvidence(file, 1, f)],
        remediation:
          "Login/OTP/ödeme uçlarına IP+kimlik bazlı rate-limit ekleyin (ör. @upstash/ratelimit), başarısız denemeleri sınırlayın, gerekirse CAPTCHA/gecikme uygulayın.",
      });
    }
    return findings;
  },
};
