import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

/**
 * A05 (canlı) — Açıkta kalan hassas dosyalar: .env, .git, kaynak map.
 * Non-destructive: yalnızca GET; içerik indirmez, imza kontrol eder.
 */

interface Target {
  path: string;
  severity: Severity;
  /** yanıtın gerçekten dosya olduğunu doğrulayan imza */
  signature: RegExp;
  title: string;
  fix: string;
}

const TARGETS: Target[] = [
  {
    path: "/.env",
    severity: "critical",
    signature: /^[A-Z0-9_]+\s*=/m,
    title: "Açıkta .env dosyası",
    fix: ".env'i public serve etmeyin; hosting rewrite/ignore kurallarını düzeltin, sızan sırları iptal edin.",
  },
  {
    path: "/.git/config",
    severity: "high",
    signature: /\[core\]|repositoryformatversion/i,
    title: "Açıkta .git dizini",
    fix: ".git dizinini web kökünden kaldırın / erişimi engelleyin.",
  },
  {
    path: "/.git/HEAD",
    severity: "high",
    signature: /ref:\s*refs\//,
    title: "Açıkta .git/HEAD",
    fix: ".git erişimini engelleyin.",
  },
];

export const liveExposedFiles: LiveRule = {
  id: "a05-live-exposed-files",
  title: "Canlı: açıkta kalan hassas dosyalar",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "high",
  kind: "live",
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const t of TARGETS) {
      const res = await ctx.probe(t.path);
      if (!res.ok) continue;
      if (res.status !== 200) continue;
      // SPA fallback (index.html döner) elemesi: HTML dönmüş ve imza yoksa geç
      if (!t.signature.test(res.bodySnippet)) continue;
      findings.push({
        ruleId: this.id,
        title: t.title,
        owasp: this.owasp,
        severity: t.severity,
        description: `${t.path} 200 döndü ve içeriği gerçek dosya imzasıyla eşleşti. Hassas dosya internete açık.`,
        evidence: [
          httpEvidence(
            res.requestLine,
            `HTTP ${res.status}\n${res.bodySnippet.slice(0, 200)}`,
          ),
        ],
        remediation: t.fix,
      });
    }
    return findings;
  },
};
