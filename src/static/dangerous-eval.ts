import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A03 — Tehlikeli yürütme / DOM enjeksiyonu:
 * dangerouslySetInnerHTML, eval, new Function, child_process (girdi ile).
 */

import type { Confidence } from "../core/finding.js";
import type { Severity } from "../core/severity.js";

type SigKind = "dom" | "eval" | "cmd";

interface Sig {
  re: RegExp;
  kind: SigKind;
  title: string;
  desc: string;
  fix: string;
}

const SIGS: Sig[] = [
  {
    re: /dangerouslySetInnerHTML/,
    kind: "dom",
    title: "dangerouslySetInnerHTML kullanımı (XSS)",
    desc: "dangerouslySetInnerHTML ile ham HTML basılıyor. İçerik kullanıcı kaynaklıysa saklı/yansıyan XSS mümkün.",
    fix: "HTML'i sanitize edin (DOMPurify) ya da düz metin/React elemanları kullanın.",
  },
  {
    re: /\beval\s*\(/,
    kind: "eval",
    title: "eval() kullanımı",
    desc: "eval() dinamik kod çalıştırır; girdi içeriyorsa uzaktan kod yürütmeye kadar gidebilir.",
    fix: "eval'i kaldırın; JSON.parse / güvenli parser / açık mantık kullanın.",
  },
  {
    re: /new\s+Function\s*\(/,
    kind: "eval",
    title: "new Function() ile dinamik kod",
    desc: "new Function(...) çalışma zamanında kod derler; eval ile aynı risk.",
    fix: "Dinamik kod üretimini kaldırın; statik mantığa çevirin.",
  },
  {
    re: /child_process|\bexec(Sync)?\s*\(|\bspawn(Sync)?\s*\(/,
    kind: "cmd",
    title: "child_process / komut çalıştırma",
    desc: "Sistem komutu çalıştırılıyor.",
    fix: "Mümkünse komut çalıştırmayın; gerekiyorsa execFile + argüman dizisi kullanın, shell:true'dan kaçının, girdiyi allowlist ile doğrulayın.",
  },
];

const INPUT_HINT = /(req\.|params|searchParams|query\.|body|input|props\.|formData|request\.|\$\{)/;
// KULLANICI/istek kaynaklı girdi (şablon literali/lokal değişken DEĞİL — build
// script'lerinde `node ${file}` gibi kullanımlar tasarım gereğidir, yükseltilmez).
const REQUEST_INPUT = /(req\.|\breq\b|params|searchParams|query\.|\bbody\b|formData|request\.|searchParams|nextUrl|await\s+request)/;
// Komutun gerçekten kullanıcı girdisiyle inşa edildiğine dair güçlü işaretler.
const CMD_TAINT = /(shell\s*:\s*true)/i;

// --- dangerouslySetInnerHTML (DOM XSS) veri-akışı yardımcıları ---
// __html değerine saldırgan-kontrollü veri akıyorsa (tainted) gerçek XSS.
const DOM_TAINT =
  /(req\.|request\.|\bparams\b|searchParams|nextUrl|query\.|\bbody\b|formData|props\.|\bprops\b|useParams|useSearchParams|\.get\(|await\s+fetch|fetch\(|cms|contentful|sanity|payload|graphql|window\.location|document\.location|location\.(search|hash|href)|getData|userInput|comment|message|description)/i;
// Değer üzerinde HTML-güvenli sanitize/escape uygulanmış → düşür/ele.
const DOM_SANITIZER =
  /(escapeJsonLd|sanitize\w*|DOMPurify|createDOMPurify|\bescapeHtml\b|\bescape\s*\(|xss\s*\(|clean\s*\()/i;

/**
 * dangerouslySetInnerHTML sink'inin `__html` değerinin saldırgan-kontrollü
 * (tainted) olup olmadığını, dosya içi tek-seviye değişken çözümlemesiyle karar verir.
 * Yalnızca `role` benzeri kimlik-bilgisi değil, tam veri-akışı incelemesi.
 */
function htmlValueTainted(valExpr: string, content: string): boolean {
  if (DOM_TAINT.test(valExpr)) return true;
  const ids = valExpr.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? [];
  const SKIP = new Set(["JSON", "stringify", "String", "__html"]);
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  for (const id of ids) {
    if (SKIP.has(id)) continue;
    // const/let/var X = <rhs>  → RHS tainted mi?
    const asg = new RegExp(
      "(?:const|let|var)\\s+" + esc(id) + "\\s*=\\s*([^\\n;]+)",
    ).exec(content);
    if (asg) {
      // Yerel bir const/literal atamasına çözülüyor → RHS tainted değilse güvenli.
      if (DOM_TAINT.test(asg[1])) return true;
      continue;
    }
    // Destructured prop / fonksiyon parametresi → prop-kaynaklı (spec'e göre tainted:
    // ebeveyn bileşenden gelen değer saldırgan-kontrollü olabilir).
    const destructured = new RegExp(
      "(?:function\\s+\\w+\\s*\\(|=>|\\(|,)\\s*\\{[^{}]*\\b" + esc(id) + "\\b[^{}]*\\}",
    );
    const positionalParam = new RegExp(
      "function\\s+\\w+\\s*\\([^)]*\\b" + esc(id) + "\\b|\\(\\s*" + esc(id) + "\\s*[,:)]",
    );
    if (destructured.test(content) || positionalParam.test(content)) return true;
  }
  return false;
}

export const dangerousEval: StaticRule = {
  id: "a03-dangerous-execution-sink",
  title: "Tehlikeli yürütme / DOM enjeksiyon noktası",
  owasp: "A03:2021-Injection",
  severity: "high",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        for (const sig of SIGS) {
          if (!sig.re.test(raw)) continue;
          const window = lines.slice(Math.max(0, i - 2), i + 4).join("\n");
          const inputNear = INPUT_HINT.test(window);

          let severity: Severity;
          let confidence: Confidence;
          let note = "";

          if (sig.kind === "dom") {
            // dangerouslySetInnerHTML: yalnızca __html değerine saldırgan-kontrollü
            // (tainted) veri akıyorsa XSS. Statik literal / JSON-LD / sanitize'lı
            // içerik FP'dir — veri-akışını izle.
            // Yorum satırındaki `dangerouslySetInnerHTML` bahsi → sink değil, ele.
            if (/^\s*(\*|\/\/|\/\*)/.test(raw)) continue;
            const ctxWin = lines
              .slice(Math.max(0, i - 1), i + 6)
              .join("\n");
            // 1) JSON-LD structured data → React'ta standart, HTML-context değil.
            if (/application\/ld\+json/i.test(ctxWin)) continue;
            // 2) __html değerini çıkar. Bulunmazsa gerçek bir sink değildir → ele.
            const hm = /__html\s*:\s*([\s\S]{0,240}?)(?:\}\s*\}|,\s*\n\s*\}|$)/.exec(
              ctxWin,
            );
            if (!hm) continue;
            const valExpr = hm[1].trim();
            if (!valExpr) continue;
            // 3) JSON.stringify(sabit) → HTML-context değil, güvenli serileştirme.
            const isJsonStringify = /^JSON\.stringify\s*\(/.test(valExpr);
            // 4) Değer bir string/template literal ile başlıyor ve interpolasyon
            //    (${...}) içermiyorsa tamamen statik içeriktir (truncate edilmiş olsa da).
            const isStaticLiteral =
              /^["'`]/.test(valExpr) && !/\$\{/.test(valExpr);
            // 5) HTML-güvenli sanitize/escape uygulanmış.
            const sanitized = DOM_SANITIZER.test(ctxWin);
            if (isJsonStringify || isStaticLiteral || sanitized) {
              // Whitelist: statik/serileştirilmiş/sanitize'lı → bildirme.
              continue;
            }
            if (htmlValueTainted(valExpr, content)) {
              // Saldırgan-kontrollü veri sink'e ulaşıyor → gerçek XSS.
              severity = "high";
              confidence = "kesin";
              note =
                " __html değerine kullanıcı/istek/DB/CMS kaynaklı veri akıyor gibi görünüyor → XSS riski.";
            } else {
              // Kaynak statik/repo-içi görünüyor → düşük, elle doğrula.
              severity = "low";
              confidence = "olası";
              note =
                " (Değer statik/repo-içi görünüyor — saldırgan-kontrollü veri tespit edilmedi; büyük olasılıkla güvenli.)";
            }
          } else if (sig.kind === "cmd") {
            // child_process çoğunlukla build/araç/sunucu kodunda tasarım gereğidir.
            // Yalnızca gerçek istek/kullanıcı girdisi komuta akıyorsa (ya da
            // shell:true varsa) yükselt; lokal `${degisken}` kullanımını yükseltme.
            const tainted = REQUEST_INPUT.test(window) || CMD_TAINT.test(window);
            severity = tainted ? "high" : "low";
            confidence = "olası";
            note = tainted
              ? " Komut kullanıcı girdisiyle inşa ediliyor gibi görünüyor → komut enjeksiyonu (RCE) riski."
              : " (Sabit/araç kullanımı gibi görünüyor — kullanıcı girdisi tespit edilmedi; büyük olasılıkla tasarım gereği.)";
          } else {
            // eval / new Function — sezgisel; girdi yakınsa yüksek, değilse orta.
            severity = inputNear ? "high" : "medium";
            confidence = "olası";
            note = inputNear ? " (Yakında kullanıcı girdisi tespit edildi.)" : "";
          }

          findings.push({
            ruleId: this.id,
            title: sig.title,
            owasp: this.owasp,
            severity,
            confidence,
            description: sig.desc + note,
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation: sig.fix,
          });
        }
      }
    }
    return findings;
  },
};
