import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — Kod içine gömülü secret / API key / token.
 * Bilinen sağlayıcı paternleri + yüksek-entropi assignment tespiti.
 */

interface Pattern {
  name: string;
  re: RegExp;
  severity: "critical" | "high";
}

const PROVIDER_PATTERNS: Pattern[] = [
  { name: "Stripe secret key", re: /sk_(live|test)_[A-Za-z0-9]{16,}/, severity: "critical" },
  { name: "Stripe restricted key", re: /rk_(live|test)_[A-Za-z0-9]{16,}/, severity: "high" },
  { name: "AWS access key", re: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "Google API key", re: /AIza[0-9A-Za-z_\-]{35}/, severity: "high" },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{36,}/, severity: "critical" },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/, severity: "high" },
  { name: "OpenAI key", re: /sk-(proj-)?[A-Za-z0-9]{20,}/, severity: "critical" },
  { name: "Supabase/JWT (service) token", re: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/, severity: "high" },
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, severity: "critical" },
  { name: "iyzico key", re: /(iyzico|IYZICO)[^\n]{0,20}(sandbox|api)[-_]?key['"\s:=]+[A-Za-z0-9]{16,}/i, severity: "high" },
];

// key = "değer" ataması; anahtar adı hassas + değer sabit uzun string
const SECRET_ASSIGN =
  /\b(secret|api[_-]?key|apikey|password|passwd|token|private[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i;

const PLACEHOLDER =
  /(process\.env|import\.meta\.env|your[_-]?|xxx|placeholder|example|changeme|<[^>]+>|\$\{)/i;

const shannon = (s: string): number => {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let h = 0;
  for (const c in freq) {
    const p = freq[c] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
};

const skipFile = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /\.env(\.example|\.sample|\.template)?$/.test(f) ||
    /(test|spec|__tests__|fixtures?)/.test(f) ||
    /\.lock$|package-lock/.test(f)
  );
};

export const hardcodedSecrets: StaticRule = {
  id: "a02-hardcoded-secret",
  title: "Kod içine gömülü secret / API anahtarı",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "critical",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (skipFile(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];

        // 1) sağlayıcı paternleri
        for (const p of PROVIDER_PATTERNS) {
          if (p.re.test(raw)) {
            const key = `${file}:${i}:${p.name}`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({
              ruleId: this.id,
              title: `${this.title} — ${p.name}`,
              owasp: this.owasp,
              severity: p.severity,
              description: `Kaynak kodunda ${p.name} paternine uyan sabit bir sır bulundu. Kod deposuna giren gizli anahtarlar sızıntı ve yetkisiz erişim riskidir.`,
              evidence: [fileEvidence(file, i + 1, raw.replace(p.re, (m) => m.slice(0, 6) + "…redacted"))],
              remediation:
                "Anahtarı koddan çıkarın, ortam değişkenine (.env, gizli yönetimi) taşıyın ve sızan anahtarı sağlayıcıda derhal iptal edip yenileyin.",
            });
          }
        }

        // 2) yüksek entropi atama
        const m = SECRET_ASSIGN.exec(raw);
        if (m) {
          const value = m[2];
          if (PLACEHOLDER.test(raw) || PLACEHOLDER.test(value)) continue;
          if (value.length >= 16 && shannon(value) >= 3.5) {
            const key = `${file}:${i}:entropy`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({
              ruleId: this.id,
              title: `${this.title} — yüksek entropili sabit değer`,
              owasp: this.owasp,
              severity: "high",
              description:
                "Hassas isimli bir değişkene (secret/token/password/api_key) sabit, yüksek-entropili bir değer atanmış. Muhtemelen gerçek bir sır.",
              evidence: [fileEvidence(file, i + 1, raw.replace(value, value.slice(0, 4) + "…redacted"))],
              remediation:
                "Değeri ortam değişkenine taşıyın; koddaki sabiti kaldırın ve gerçek sırsa iptal/yenileyin.",
            });
          }
        }
      }
    }
    return findings;
  },
};
