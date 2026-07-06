import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A01 — Supabase service_role anahtarı kullanımı (RLS bypass riski).
 * service_role key RLS'i tamamen atlar; client'a sızarsa ya da yanlış route'ta
 * kullanılırsa tüm veriye erişim açılır.
 */

const SERVICE_ROLE =
  /(SERVICE_ROLE|service_role|SUPABASE_SERVICE_KEY|supabaseServiceRole|serviceRoleKey)/;

const isClientBundle = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return /\.(tsx|jsx)$/.test(f) || /(^|\/)components\//.test(f);
};

export const supabaseServiceRole: StaticRule = {
  id: "a01-supabase-service-role-key",
  title: "Supabase service_role anahtarı kullanımı (RLS bypass)",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const matches = ctx.grep(SERVICE_ROLE, (f) => !/\.env/.test(f));
    const seen = new Set<string>();
    for (const m of matches) {
      const key = `${m.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const content = ctx.read(m.file) ?? "";
      const clientSide =
        /["']use client["']/.test(content) || isClientBundle(m.file);
      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: clientSide ? "critical" : "high",
        description: clientSide
          ? "service_role anahtarı client tarafı (use client / .tsx) bir dosyada geçiyor. Bu anahtar RLS'i tamamen atlar ve tarayıcıya sızarsa tüm veriye tam erişim demektir."
          : "service_role anahtarı sunucu kodunda kullanılıyor. RLS'i atladığı için yalnızca gerçekten gerekli, katı yetki kontrollü uçlarda kullanılmalı; yanlışlıkla client'a taşınmadığından emin olun.",
        evidence: [fileEvidence(m.file, m.line, m.text)],
        remediation:
          "service_role anahtarını asla client bundle'ına koymayın. Sadece sunucu tarafında, minimum uçta ve manuel yetki kontrolüyle kullanın; mümkünse anon key + RLS tercih edin.",
      });
    }
    return findings;
  },
};
