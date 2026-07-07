import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveContext, LiveRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

/**
 * A05 (canlı) — Açıkta kalan hassas dosyalar (genişletilmiş).
 *
 * `a05-live-exposed-files` /.env, /.git/config ve /.git/HEAD'i kapsar; bu kural
 * onu TAMAMLAR (çakışmaz): .env.local/.env.production, .env yedekleri, config.json,
 * DB dump/yedek dosyaları ve açıkta kalan kaynak haritaları (.js.map).
 *
 * SPA 200-catch-all koruması: her hedefin, yanıtın GERÇEKTEN o dosya olduğunu
 * doğrulayan bir imzası vardır (yoksa geç). Doğrulanmış bulgular → "kesin".
 */

interface Target {
  path: string;
  severity: Severity;
  signature: RegExp;
  title: string;
  fix: string;
}

const TARGETS: Target[] = [
  {
    path: "/.env.local",
    severity: "critical",
    signature: /^[A-Z0-9_]+\s*=/m,
    title: "Açıkta .env.local dosyası",
    fix: ".env.local'ı public serve etmeyin; hosting rewrite/ignore kurallarını düzeltin, sızan sırları iptal edin.",
  },
  {
    path: "/.env.production",
    severity: "critical",
    signature: /^[A-Z0-9_]+\s*=/m,
    title: "Açıkta .env.production dosyası",
    fix: ".env.production'ı public serve etmeyin; sızan tüm sırları iptal edip yenileyin.",
  },
  {
    path: "/.env.bak",
    severity: "critical",
    signature: /^[A-Z0-9_]+\s*=/m,
    title: "Açıkta .env yedeği (.env.bak)",
    fix: "Yedek env dosyasını kaldırın; sızan sırları iptal edin.",
  },
  {
    path: "/backup.sql",
    severity: "high",
    signature: /(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump|DROP TABLE)/i,
    title: "Açıkta veritabanı yedeği (backup.sql)",
    fix: "DB dump dosyasını web kökünden kaldırın; içerik sızmışsa etkilenen kayıtları/sırları değerlendirin.",
  },
  {
    path: "/dump.sql",
    severity: "high",
    signature: /(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump|DROP TABLE)/i,
    title: "Açıkta veritabanı dökümü (dump.sql)",
    fix: "DB dump dosyasını web kökünden kaldırın.",
  },
  {
    path: "/database.sql",
    severity: "high",
    signature: /(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump|DROP TABLE)/i,
    title: "Açıkta veritabanı şeması/dökümü (database.sql)",
    fix: "SQL dosyasını web kökünden kaldırın.",
  },
];

/** config.json içinde sır-benzeri anahtar var mı (aksi hâlde iyi huylu public config). */
const CONFIG_SECRET_RE =
  /"(?:[a-zA-Z_]*(?:password|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|service[_-]?role|client[_-]?secret)[a-zA-Z_]*)"\s*:\s*"[^"]{6,}"/i;

/** Kaynak haritası imzası. */
const SOURCEMAP_RE = /"version"\s*:\s*3[\s\S]*"sources"\s*:/;

/** "/" yanıtından ilk gerçek JS bundle yolunu çek (kaynak haritası kontrolü için). */
function firstScriptSrc(html: string): string | null {
  const re = /<script[^>]+src=["']([^"']+\.js)(\?[^"']*)?["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const src = m[1];
    // yalnızca aynı-origin (relative) bundle'ları kontrol et
    if (src.startsWith("/") && !src.startsWith("//")) return src;
  }
  return null;
}

async function checkConfigJson(ctx: LiveContext, findings: Finding[], ruleId: string, owasp: Finding["owasp"]): Promise<void> {
  const res = await ctx.probe("/config.json");
  if (!res.ok || res.status !== 200) return;
  // JSON + sır-benzeri anahtar şart (public config.json'ları elemek için).
  if (!/^\s*[[{]/.test(res.bodySnippet)) return;
  if (!CONFIG_SECRET_RE.test(res.bodySnippet)) return;
  findings.push({
    ruleId,
    title: "Açıkta sır içeren config.json",
    owasp,
    severity: "high",
    confidence: "kesin",
    cwe: "CWE-538",
    description:
      "/config.json 200 döndü ve içinde sır-benzeri anahtarlar (password/secret/token/apiKey vb.) tespit edildi. Yapılandırma sırları internete açık.",
    evidence: [httpEvidence(res.requestLine, `HTTP ${res.status}\n${res.bodySnippet.slice(0, 200)}`)],
    remediation:
      "Sır içeren config.json'ı public dizinden kaldırın; sırları sunucu-tarafı env'e taşıyıp iptal/yenileyin.",
  });
}

async function checkSourceMap(ctx: LiveContext, findings: Finding[], ruleId: string, owasp: Finding["owasp"]): Promise<void> {
  const root = await ctx.probe("/");
  if (!root.ok || root.status !== 200) return;
  const script = firstScriptSrc(root.bodySnippet);
  if (!script) return;
  const mapRes = await ctx.probe(`${script}.map`);
  if (!mapRes.ok || mapRes.status !== 200) return;
  if (!SOURCEMAP_RE.test(mapRes.bodySnippet)) return;
  findings.push({
    ruleId,
    title: "Açıkta kaynak haritası (.js.map)",
    owasp,
    severity: "medium",
    confidence: "kesin",
    cwe: "CWE-540",
    description: `${script}.map 200 döndü ve geçerli bir source map imzası taşıyor. Kaynak haritaları özgün (minify öncesi) kaynak kodu, yorumları ve iç yol yapısını sızdırır.`,
    evidence: [httpEvidence(mapRes.requestLine, `HTTP ${mapRes.status}\n${mapRes.bodySnippet.slice(0, 160)}`)],
    remediation:
      "Üretimde source map üretimini kapatın (Next: productionBrowserSourceMaps:false, Vite: build.sourcemap:false) veya .map dosyalarına public erişimi engelleyin.",
  });
}

export const liveExposedSecrets: LiveRule = {
  id: "a05-live-exposed-secrets",
  title: "Canlı: açıkta env yedeği / DB dump / config / source map",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "high",
  kind: "live",
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const t of TARGETS) {
      const res = await ctx.probe(t.path);
      if (!res.ok || res.status !== 200) continue;
      // SPA fallback (index.html) elemesi: imza yoksa geç.
      if (!t.signature.test(res.bodySnippet)) continue;
      findings.push({
        ruleId: this.id,
        title: t.title,
        owasp: this.owasp,
        severity: t.severity,
        confidence: "kesin",
        cwe: "CWE-538",
        description: `${t.path} 200 döndü ve içeriği gerçek dosya imzasıyla eşleşti. Hassas dosya internete açık.`,
        evidence: [httpEvidence(res.requestLine, `HTTP ${res.status}\n${res.bodySnippet.slice(0, 200)}`)],
        remediation: t.fix,
      });
    }
    await checkConfigJson(ctx, findings, this.id, this.owasp);
    await checkSourceMap(ctx, findings, this.id, this.owasp);
    return findings;
  },
};
