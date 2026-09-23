import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A08 — no Subresource Integrity (SRI) on an external <script>.
 *
 * When a script loaded from a third-party CDN carries no `integrity` attribute,
 * a compromised or modified CDN can execute malicious code (supply chain).
 */

// A <script ... src="http(s)://..."> opening tag (line breaks inside the tag allowed).
const SCRIPT_TAG = /<script\b[^>]*\bsrc\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gis;
const HAS_INTEGRITY = /\bintegrity\s*=/i;
const LOCALHOST = /https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i;

const isMarkupFile = (file: string): boolean =>
  /\.(html?|tsx|jsx)$/.test(file.replace(/\\/g, "/"));

/**
 * Bu dosya, BAŞKA BİR SİTENİN kaydedilmiş kopyası mı?
 *
 * Referans/tasarım amacıyla kaydedilmiş tam sayfa render'ları depoda sık durur.
 * Onların script'lerine SRI eklemek anlamsızdır: dosya hiç yayınlanmaz ve
 * script'ler zaten bizim değildir.
 *
 * Gerçek vaka: firstvega-landing'de `src/brand/{fv,vw}.html` iki WordPress
 * sitesinin kaydedilmiş hâliydi ve TEK BAŞLARINA 75 bulgu üretip projeyi
 * portföyün ikinci en riskli projesi gösteriyordu (skor 227). `build.py` bu
 * klasöre hiç dokunmuyor, `dist/` içine de girmiyor.
 *
 * Ayırt edici ölçüldü: kopyada `canonical` hangi adresi gösteriyorsa harici
 * script'lerin TAMAMI da o adreste ve GÖRELİ script yok. Projenin kendi
 * sayfasında ise varlıklar göreli gelir. Tek başına "çok sayıda mutlak script"
 * yetmez — CDN kullanan gerçek bir sayfa da öyle görünür; belirleyici olan
 * script'lerin canonical ile AYNI konakta toplanması.
 */
function baskaSitenSayfasi(content: string): boolean {
  const kanonik =
    /<link[^>]+rel=["']canonical["'][^>]+href=["']https?:\/\/([^/"']+)/i.exec(content) ??
    /<meta[^>]+property=["']og:url["'][^>]+content=["']https?:\/\/([^/"']+)/i.exec(content);
  if (!kanonik) return false;
  const konak = kanonik[1].toLowerCase().replace(/^www\./, "");

  /**
   * Gömülü oynatıcı / etiket yöneticisi konakları paydadan ÇIKARILIR.
   * Kaydedilmiş bir sayfada Vimeo, YouTube, GTM, Facebook script'leri de bulunur;
   * bunları saymak oranı düşürüp kopyayı "gerçek sayfa" gibi gösteriyordu
   * (vegawest kopyası 21 Vimeo script'i yüzünden 0,60'ta kalmıştı).
   * Bu konaklar hem kopyada hem gerçek sayfada olur — ayırt edici değiller.
   */
  const GOMU_KONAK =
    /(^|\.)(vimeo|youtube|youtube-nocookie|ytimg|googletagmanager|google-analytics|doubleclick|facebook|fbcdn|twitter|x|linkedin|hotjar|clarity\.ms|tiktok)\.[a-z.]+$|^(google|gstatic)\.com$/i;

  const mutlak = [...content.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']https?:\/\/([^/"']+)/gi)]
    .map((m) => m[1].toLowerCase().replace(/^www\./, ""))
    .filter((h) => !GOMU_KONAK.test(h));
  if (mutlak.length < 5) return false;

  const ayni = mutlak.filter((h) => h === konak).length;
  const goreli = (content.match(/<script\b[^>]*\bsrc\s*=\s*["']\/[^/]/gi) ?? []).length;

  // Script'lerin ezici çoğunluğu canonical'ın konağında VE göreli script yok.
  return ayni / mutlak.length >= 0.8 && goreli === 0;
}

export const externalScriptSri: StaticRule = {
  id: "a08-external-script-no-sri",
  title: "Harici script'te SRI (integrity) yok",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "medium",
  cwe: "CWE-353",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (!isMarkupFile(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      // Başka bir sitenin KAYDEDİLMİŞ kopyasıysa, oradaki script'ler bizim
      // sorumluluğumuzda değildir — bkz. baskaSitenSayfasi.
      if (baskaSitenSayfasi(content)) continue;

      const rx = new RegExp(SCRIPT_TAG.source, SCRIPT_TAG.flags);
      let m: RegExpExecArray | null;
      while ((m = rx.exec(content)) !== null) {
        const tag = m[0];
        if (HAS_INTEGRITY.test(tag)) continue;
        if (LOCALHOST.test(tag)) continue;
        const line = content.slice(0, m.index).split(/\r?\n/).length;
        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "medium",
          cwe: this.cwe,
          description:
            "A <script> loaded from a third-party origin declares no integrity (SRI) hash. If the CDN is compromised or the file is modified, the browser executes the malicious code without noticing the change.",
          evidence: [fileEvidence(file, line, tag.replace(/\s+/g, " ").slice(0, 200))],
          remediation:
            "Add integrity (sha384) and crossorigin='anonymous' to external scripts, and self-host critical dependencies where you can.",
          remediationCode:
            '<script src="https://cdn.example.com/lib.js"\n' +
            '        integrity="sha384-..." crossorigin="anonymous"></script>',
        });
      }
    }
    return findings;
  },
};
