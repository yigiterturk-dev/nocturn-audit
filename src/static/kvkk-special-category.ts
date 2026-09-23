import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * Special-category personal data (GDPR Article 9 / KVKK Article 6) — informational.
 *
 * When fields for health, biometric, genetic, religious, ethnic, political,
 * sexual, trade-union or criminal-record data are detected, this reminds you that
 * such data needs explicit consent plus additional safeguards.
 * Informational only — on its own it is not a vulnerability.
 */

// Note: long, distinctive tokens may take an optional suffix (health_notes, medical_record).
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
  title: "Special-category personal data detected (GDPR Art. 9 / KVKK Art. 6)",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "info",
  cwe: "CWE-359",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
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
        // skip comment lines
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
            "This field looks like special-category personal data (health, biometric, genetic, religious, ethnic, political, sexual or criminal) under GDPR Article 9 and KVKK Article 6. Such data may only be processed with explicit consent or a statutory exemption, and requires additional technical and organisational measures: encryption, restricted access and separate audit logs.",
          evidence: [fileEvidence(file, i + 1, raw)],
          remediation:
            "Confirm the legal basis (explicit consent) for this field, and apply field-level encryption, strict access control and a separate audit trail, following the regulator's guidance on special-category data.",
        });
      }
    }
    return findings;
  },
};
