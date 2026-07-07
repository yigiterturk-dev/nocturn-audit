import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A01 — IDOR paterni.
 * İstek parametresinden gelen id doğrudan sorguda kullanılıyor,
 * ownership (user_id/owner eşleşmesi) kontrolü yakınlarda yok.
 */

// GERÇEK nesne-ID kaynakları. 'format' gibi davranışsal query param'ları IDOR değildir
// → yalnızca id/slug/uuid/*Id benzeri anahtarları yakala.
const ID_SOURCE =
  /(params\.(id|slug|uuid|userId|\w*Id)\b|searchParams\.get\(\s*['"`](id|slug|uuid|\w*[iI]d|leadId|conversation_id)['"`]\s*\)|req\.query\.(id|\w*[iI]d)\b|query\.\w*[iI]d\b)/;

// bu id ile doğrudan tekil sorgu
const QUERY_USE =
  /\.(eq|findUnique|findFirst|findById|where)\s*\(|WHERE\s+id\s*=/i;

const OWNERSHIP_HINTS =
  /(user_id|userId|owner|ownerId|auth\.uid\(\)|session\.user|currentUser|\.eq\(\s*['"]user)/i;

// Route/handler ownership sınırı bir guard ile korunuyorsa (requireAdmin/requireGate/
// requireAuth) ve uygulama tek-kiracılı ise IDOR uygulanamaz → dosyayı ele.
const GUARD_HINTS =
  /(requireAdmin|requireGate|requireAuth|requireUser|requireSession|ensureAuth|assertAdmin|getServerSession|isAdmin\b|\bauth\(\)\s*;?)/i;

export const idorDirectObject: StaticRule = {
  id: "a01-idor-direct-object-reference",
  title: "Olası IDOR: ownership kontrolsüz doğrudan nesne erişimi",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      const f = file.replace(/\\/g, "/");
      if (!/(app\/|pages\/api\/|route\.|\/api\/|actions?\.|lib\/)/.test(f))
        continue;
      const content = ctx.read(file);
      if (!content) continue;
      // Dosyada bir guard varsa (requireAdmin/requireGate/requireAuth) ownership sınırı
      // zaten korunuyor; tek-kiracılı/tek-admin uygulamada IDOR uygulanamaz → ele.
      if (GUARD_HINTS.test(content)) continue;
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        if (!ID_SOURCE.test(lines[i])) continue;
        // aynı ya da sonraki ~8 satırda doğrudan sorgu kullanımı ara
        const window = lines.slice(i, i + 9).join("\n");
        if (!QUERY_USE.test(window)) continue;
        // ownership kontrolü var mı (geniş pencere)
        const contextWindow = lines
          .slice(Math.max(0, i - 6), i + 12)
          .join("\n");
        if (OWNERSHIP_HINTS.test(contextWindow)) continue;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "high",
          description:
            "İstekten gelen id doğrudan tekil kayıt sorgusunda kullanılıyor ama yakında ownership (user_id/owner) filtresi yok. Başka kullanıcının kaydına erişim (IDOR) mümkün olabilir.",
          evidence: [fileEvidence(file, i + 1, lines[i])],
          remediation:
            "Sorguya oturumdaki kullanıcı kimliğini de ekleyin (ör. .eq('user_id', session.user.id)) veya RLS ile satır bazlı erişimi zorunlu kılın.",
        });
        break; // dosya başına bir bulgu yeter
      }
    }
    return findings;
  },
};
