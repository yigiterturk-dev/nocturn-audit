import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A03 — Tehlikeli yürütme / DOM enjeksiyonu:
 * dangerouslySetInnerHTML, eval, new Function, child_process (girdi ile).
 */

interface Sig {
  re: RegExp;
  title: string;
  severity: "critical" | "high" | "medium";
  desc: string;
  fix: string;
}

const SIGS: Sig[] = [
  {
    re: /dangerouslySetInnerHTML/,
    title: "dangerouslySetInnerHTML kullanımı (XSS)",
    severity: "high",
    desc: "dangerouslySetInnerHTML ile ham HTML basılıyor. İçerik kullanıcı kaynaklıysa saklı/yansıyan XSS mümkün.",
    fix: "HTML'i sanitize edin (DOMPurify) ya da düz metin/React elemanları kullanın.",
  },
  {
    re: /\beval\s*\(/,
    title: "eval() kullanımı",
    severity: "high",
    desc: "eval() dinamik kod çalıştırır; girdi içeriyorsa uzaktan kod yürütmeye kadar gidebilir.",
    fix: "eval'i kaldırın; JSON.parse / güvenli parser / açık mantık kullanın.",
  },
  {
    re: /new\s+Function\s*\(/,
    title: "new Function() ile dinamik kod",
    severity: "high",
    desc: "new Function(...) çalışma zamanında kod derler; eval ile aynı risk.",
    fix: "Dinamik kod üretimini kaldırın; statik mantığa çevirin.",
  },
  {
    re: /child_process|\bexec(Sync)?\s*\(|\bspawn(Sync)?\s*\(/,
    title: "child_process / komut çalıştırma",
    severity: "high",
    desc: "Sistem komutu çalıştırılıyor. Argümanlar girdi içeriyorsa komut enjeksiyonu (RCE) riski.",
    fix: "Mümkünse komut çalıştırmayın; gerekiyorsa execFile + argüman dizisi kullanın, shell:true'dan kaçının, girdiyi allowlist ile doğrulayın.",
  },
];

const INPUT_HINT = /(req\.|params|searchParams|query\.|body|input|props\.|formData|request\.|\$\{)/;

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
          const inputNear = INPUT_HINT.test(
            lines.slice(Math.max(0, i - 2), i + 4).join("\n"),
          );
          const sev =
            sig.severity === "high" && inputNear && sig.re.source.includes("child_process")
              ? "critical"
              : sig.severity;
          findings.push({
            ruleId: this.id,
            title: sig.title,
            owasp: this.owasp,
            severity: sev,
            description: sig.desc + (inputNear ? " (Yakında kullanıcı girdisi tespit edildi.)" : ""),
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation: sig.fix,
          });
        }
      }
    }
    return findings;
  },
};
