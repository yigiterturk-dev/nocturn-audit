import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — .env dosyası depoda / .gitignore'da değil.
 * Gerçek sır içeren .env dosyaları git'e girmemeli.
 */

export const envCommitted: StaticRule = {
  id: "a02-env-file-committed",
  title: ".env dosyası git'e commit edilmiş",
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

      const tracked = ctx.isTracked(file);
      if (tracked) {
        // GERÇEK sızıntı: dosya git tarafından izleniyor → depoya girmiş.
        findings.push({
          ruleId: this.id,
          title: `${base} dosyası git'e commit edilmiş`,
          owasp: this.owasp,
          severity: "high",
          confidence: "kesin",
          description: `${base} gerçek görünümlü değerler içeriyor ve git tarafından izleniyor (commit edilmiş). Depoyu klonlayan herkes bu sırlara erişir — açık bir sır sızıntısıdır.`,
          evidence: [fileEvidence(file, 1, "(.env içeriği redakte edildi)")],
          remediation:
            "Dosyayı takipten çıkarın (git rm --cached), .gitignore'a `.env*` ekleyin, git geçmişinden temizleyin (git filter-repo/BFG) ve açığa çıkan tüm sırları iptal edip yenileyin.",
        });
      } else if (ctx.isGitRepo) {
        // Dosya diskte var ama git izlemiyor (gitignore'lanmış): sırların DOĞRU yeri.
        // Kod-içi/commit sızıntısı değildir → yalnızca bilgi amaçlı düşük not.
        findings.push({
          ruleId: this.id,
          title: `${base} yerelde mevcut (git izlemiyor)`,
          owasp: this.owasp,
          severity: "info",
          confidence: "kesin",
          description: `${base} kaynak ağacında var ancak git tarafından izlenmiyor (gitignore'lanmış). Bu, ortam sırlarının doğru saklandığı beklenen durumdur; bir sızıntı değildir. Yine de dosyayı asla commit'lemeyin.`,
          evidence: [fileEvidence(file, 1, "(gitignore'lanmış .env — sızıntı yok)")],
          remediation:
            "Aksiyon gerekmez. Dosyanın `.gitignore` kapsamında kaldığından emin olun.",
        });
      }
      // git deposu değilse: izleme bilgisi yok → sessiz geç (FP üretme).
    }

    // hiç .gitignore yoksa ya da .env kalıbı yoksa ileriye dönük düşük uyarı
    if (!ignoresEnv && ctx.exists("package.json")) {
      findings.push({
        ruleId: this.id,
        title: ".gitignore .env kalıbı içermiyor",
        owasp: this.owasp,
        severity: "low",
        confidence: "olası",
        description:
          ".gitignore dosyası .env* için bir kural içermiyor. İleride yanlışlıkla sır commit'lenmesini önlemek için eklenmeli.",
        evidence: [fileEvidence(".gitignore", 1, gitignore ? "(.env kalıbı yok)" : "(.gitignore yok)")],
        remediation: ".gitignore'a `.env*` (ve `!.env.example`) satırlarını ekleyin.",
      });
    }

    return findings;
  },
};
