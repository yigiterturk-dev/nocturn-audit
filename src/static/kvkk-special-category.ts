import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * KVKK / GDPR özel nitelikli (special-category) veri — bilgilendirme.
 *
 * Sağlık, biyometrik, genetik, din/inanç, etnik köken, siyasi görüş, cinsel hayat,
 * sendika üyeliği, ceza/sabıka gibi özel nitelikli kişisel veri alanları tespit edilirse;
 * KVKK md.6 (ve GDPR Art.9) uyarınca açık rıza + ek koruma gereksinimini hatırlatır.
 * Yalnızca bilgilendirme (info) — tek başına "açık" değildir.
 */

// Not: uzun/ayırt edici tokenlar isteğe bağlı ek (health_notes, medical_record) alabilir.
const SPECIAL_CATEGORY =
  /\b(health(?:[_-]?\w+)?|medical(?:[_-]?\w+)?|saglik(?:[_-]?\w+)?|sağlık(?:[_-]?\w+)?|hasta(?:[_-]?\w+)?|diagnos(?:is|e)|tani|tanı|disability|engelli|blood[_-]?type|kan[_-]?grubu|biometric(?:[_-]?\w+)?|biyometrik(?:[_-]?\w+)?|fingerprint|parmak[_-]?izi|face[_-]?id|genetic(?:[_-]?\w+)?|genetik(?:[_-]?\w+)?|dna|religion(?:[_-]?\w+)?|religious|dini|inanc|inanç|mezhep|ethnic(?:[_-]?\w+)?|etnik(?:[_-]?\w+)?|irk|ırk|political(?:[_-]?\w+)?|siyasi|siyasal|philosophical|felsefi|union[_-]?member(?:ship)?|sendika(?:[_-]?\w+)?|sexual(?:[_-]?\w+)?|cinsel(?:[_-]?\w+)?|criminal(?:[_-]?\w+)?|sabika|sabıka|ceza[_-]?kaydi)\b/i;

const COLUMN_ISH =
  /\b(text|varchar|char|string|boolean|bool|jsonb?|date|enum|integer|int)\b|:\s*(text|varchar|string|boolean|enum)\s*\(|\bString\b|\bBoolean\b/i;

const isRelevantFile = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /\.(sql|prisma)$/.test(f) ||
    /(^|\/)(schema|migrations?|models?|db|types?)(\/|\.|$)/i.test(f)
  );
};

export const kvkkSpecialCategory: StaticRule = {
  id: "kvkk-special-category-data",
  title: "KVKK özel nitelikli kişisel veri tespit edildi",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "info",
  cwe: "CWE-359",
  kind: "static",
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (!isRelevantFile(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!SPECIAL_CATEGORY.test(raw)) continue;
        if (!COLUMN_ISH.test(raw)) continue;
        // yorum satırlarını atla
        if (/^\s*(--|\/\/|\*|#)/.test(raw)) continue;

        const key = `${file}:${i}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "info",
          cwe: this.cwe,
          description:
            "Bu alan KVKK md.6 kapsamında özel nitelikli (sağlık/biyometrik/genetik/din/etnik/siyasi/cinsel/ceza vb.) kişisel veri gibi görünüyor. Özel nitelikli veriler yalnızca açık rıza (veya kanunda öngörülen istisna) ile işlenebilir; ek teknik/idari tedbir (şifreleme, erişim kısıtı, ayrı log) gerektirir.",
          evidence: [fileEvidence(file, i + 1, raw)],
          remediation:
            "Bu alan için hukuki dayanağı (açık rıza) doğrulayın; alan-bazlı şifreleme, sıkı erişim kontrolü ve ayrı denetim kaydı uygulayın. KVKK Kurulu'nun özel nitelikli veri güvenlik önlemlerine uyun.",
        });
      }
    }
    return findings;
  },
};
