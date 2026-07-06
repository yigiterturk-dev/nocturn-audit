import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — .env dosyası depoda / .gitignore'da değil.
 * Gerçek sır içeren .env dosyaları git'e girmemeli.
 */

export const envCommitted: StaticRule = {
  id: "a02-env-file-committed",
  title: ".env dosyası .gitignore'da değil / depoya sızmış olabilir",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const gitignore = ctx.read(".gitignore") ?? "";
    const ignoresEnv =
      /^\s*\.env(\*|\.local|\.\*)?\s*$/m.test(gitignore) ||
      /^\s*\*?\.env\*?\s*$/m.test(gitignore) ||
      /(^|\n)\s*\.env(\b|\*)/.test(gitignore);

    const envFiles = ctx.files.filter((f) => {
      const base = f.replace(/\\/g, "/").split("/").pop() ?? "";
      return /^\.env/.test(base) && !/\.example|\.sample|\.template/.test(base);
    });

    // gerçek secret içeren .env dosyaları (example/sample/template zaten elenmiş)
    for (const file of envFiles) {
      const base = (file.replace(/\\/g, "/").split("/").pop() ?? "");
      const content = ctx.read(file) ?? "";
      const hasRealValue = /^[A-Z0-9_]+\s*=\s*[^\s#][^\n]{6,}/m.test(content);
      if (!hasRealValue) continue;
      findings.push({
        ruleId: this.id,
        title: `Gerçek değer içeren ${base} dosyası depoda`,
        owasp: this.owasp,
        severity: ignoresEnv ? "medium" : "high",
        description: ignoresEnv
          ? `${base} dosyası kaynak ağacında bulunuyor. .gitignore .env kalıbı içeriyor gibi görünse de dosya yine de mevcut; geçmişte commit edilmiş olabilir.`
          : `${base} gerçek görünümlü değerler içeriyor ve .gitignore'da .env kalıbı yok. Sırlar git geçmişine sızmış olabilir.`,
        evidence: [fileEvidence(file, 1, "(.env içeriği redakte edildi)")],
        remediation:
          ".env* dosyalarını .gitignore'a ekleyin; git geçmişinden temizleyin (git filter-repo/BFG); açığa çıkmış tüm sırları iptal edip yenileyin.",
      });
    }

    // hiç .gitignore yoksa ya da .env kalıbı yoksa bilgi ver
    if (!ignoresEnv && ctx.exists("package.json")) {
      findings.push({
        ruleId: this.id,
        title: ".gitignore .env kalıbı içermiyor",
        owasp: this.owasp,
        severity: "low",
        description:
          ".gitignore dosyası .env* için bir kural içermiyor. İleride yanlışlıkla sır commit'lenmesini önlemek için eklenmeli.",
        evidence: [fileEvidence(".gitignore", 1, gitignore ? "(.env kalıbı yok)" : "(.gitignore yok)")],
        remediation: ".gitignore'a `.env*` (ve `!.env.example`) satırlarını ekleyin.",
      });
    }

    return findings;
  },
};
