import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — NEXT_PUBLIC_ / VITE_ altında gizli anahtar.
 * Bu önekler client bundle'ına girer; secret/service/private isimli değişkenler sızar.
 */

const PUBLIC_SECRET =
  /\b(NEXT_PUBLIC_|VITE_)([A-Z0-9_]*?(SECRET|SERVICE_ROLE|PRIVATE|SERVICE_KEY|API_SECRET|CLIENT_SECRET|PASSWORD|TOKEN|STRIPE_SK|SK_LIVE|WEBHOOK_SECRET)[A-Z0-9_]*)/;

// tolere edilenler: yayınlanması normal public anahtarlar
const BENIGN =
  /(PUBLISHABLE|ANON_KEY|PUBLIC_KEY|CLERK_PUBLISHABLE|GA_|GTM_|SENTRY_DSN|MAPBOX|POSTHOG)/;

export const nextPublicSecret: StaticRule = {
  id: "a02-next-public-secret-leak",
  title: "İstemciye sızan gizli anahtar (NEXT_PUBLIC_/VITE_)",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "critical",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const matches = ctx.grep(PUBLIC_SECRET);
    for (const m of matches) {
      if (BENIGN.test(m.text)) continue;
      const key = `${m.file}:${m.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "critical",
        description:
          "NEXT_PUBLIC_ / VITE_ önekli değişkenler client bundle'ına gömülür. Bu isim bir sır (secret/service_role/private/token) ima ediyor — tarayıcıya sızıyor demektir.",
        evidence: [fileEvidence(m.file, m.line, m.text)],
        remediation:
          "Gizli değeri NEXT_PUBLIC_/VITE_ önekinden çıkarın; yalnızca sunucuda okuyun. Sızmış anahtarı iptal edip yenileyin.",
      });
    }
    return findings;
  },
};
