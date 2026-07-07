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
            // Ham HTML enjeksiyon noktası — deterministik sink.
            severity = "high";
            confidence = "kesin";
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
