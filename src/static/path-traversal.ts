import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { cagrilariGez, moduldenMi, lineNo, lineText } from "../core/ast.js";
import { buildTaintIndex, isTainted } from "../core/taint.js";

/**
 * A01 — Path traversal (CWE-22).
 *
 * A file path built from user input and handed to a filesystem sink lets an
 * attacker read or write arbitrary files (`../../etc/passwd`). The tree is the
 * source: `fs.readFile` only counts when it resolves to the `fs` module, and
 * only when the path argument is tainted. Taint is resolved CROSS-FILE: a
 * value built in one function and consumed here is still caught.
 */

const FS_SINKS = [
  "readFile", "readFileSync", "writeFile", "writeFileSync",
  "createReadStream", "createWriteStream", "appendFile", "appendFileSync",
  "unlink", "unlinkSync", "rm", "rmSync", "rename", "renameSync",
  "open", "openSync", "stat", "statSync", "access", "accessSync",
];

/** Is the path argument a fixed literal (no interpolation, no variable)? */
function sabitYolMi(arg: string): boolean {
  const t = arg.trim();
  if (!t) return false;
  if (/^["'`]/.test(t) && !/\$\{/.test(t)) return true;
  return false;
}

export const pathTraversal: StaticRule = {
  id: "a01-path-traversal",
  title: "Possible path traversal: filesystem path built from user input",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  cwe: "CWE-22",
  kind: "static",
  requires: ["js"],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const index = buildTaintIndex(ctx);

    /**
     * YOL GEÇİŞİ, YOLU SALDIRGAN SEÇEBİLİYORSA AÇIKTIR.
     *
     * Bir CLI aracında "kullanıcı girdisi" = `process.argv`. Onu veren kişi zaten
     * kabuğa sahiptir; `../../etc/passwd` yazmak yerine dosyayı doğrudan okur.
     * Orada yol geçişi diye bir tehdit yoktur.
     *
     * Portföy taramasında bu tek varsayım 15 bulgunun TAMAMINI üretti:
     * `tools/ajan-panel/core.mjs` (HTTP yüzeyi sıfır, yerel panel),
     * `nocturn-proofrepo/src/scan.ts` ("bana bir klasör ver, tara"),
     * [KOD-ADI] yedek kütüphanesi, [KOD-ADI]-stock içe aktarma betiği...
     * Onbeş sahte "high", gerçek bulguları listede görünmez yapar.
     *
     * Şart: dosyanın KENDİSİNDE bir istek yüzeyi olmalı ya da onu İÇE AKTARAN
     * bir dosyada olmalı (yardımcı modüller rota tarafından çağrılabilir —
     * onları kör etmemek için ikinci koşul şart).
     */
    const ISTEK_YUZEYI =
      /\b(NextRequest|NextResponse|IncomingMessage|ServerResponse|FastifyRequest|createServer|express\s*\(|fastify\s*\(|new\s+Hono|\breq\.(query|params|body|url|headers)|request\.(query|params|json|formData)|searchParams|useSearchParams)\b/;

    // Bir Next/Nuxt rota dosyası, içinde `req.query` geçmese bile TANIMI GEREĞİ
    // istek yüzeyidir; dışarıdan gelen değeri bir yardımcıya devredip sonucu
    // kullanabilir. Yalnız metne bakmak bu durumu kaçırıyordu (mevcut bir
    // çapraz-dosya taint testi bu yüzden kırıldı — iyi ki vardı).
    const ROTA_DOSYASI = /(^|\/)(app|pages)\/.*\/route\.(ts|tsx|js|mjs)$|(^|\/)pages\/api\/|(^|\/)server\/api\//;
    const HTTP_HANDLER = /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|export\s+default\s+(async\s+)?function\s+handler\b/;

    const yuzeyliDosyalar = new Set<string>();
    for (const f of ctx.files) {
      const c = ctx.read(f);
      if (!c) continue;
      const yol = f.replace(/\\/g, "/");
      if (ISTEK_YUZEYI.test(c) || ROTA_DOSYASI.test(yol) || HTTP_HANDLER.test(c)) {
        yuzeyliDosyalar.add(f);
      }
    }

    /** Bu dosya bir isteğe bağlanabilir mi? (kendisi ya da onu içe aktaran) */
    const istegeBagli = (file: string): boolean => {
      if (yuzeyliDosyalar.has(file)) return true;
      const ad = (file.split(/[\\/]/).pop() ?? "").replace(/\.(ts|tsx|js|mjs|cjs)$/, "");
      if (!ad) return false;
      const desen = new RegExp(`from\\s+["'][^"']*\\b${ad}["']|require\\(["'][^"']*\\b${ad}["']\\)`);
      for (const f of yuzeyliDosyalar) {
        if (f === file) continue;
        const c = ctx.read(f);
        if (c && desen.test(c)) return true;
      }
      return false;
    };

    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      // İstek yüzeyi yoksa bu dosyada yol geçişi bir tehdit modeli değildir.
      if (!istegeBagli(file)) continue;
      const ast = ctx.ast(file);
      if (!ast) continue;

      cagrilariGez(ast, (c) => {
        if (!moduldenMi(ast, c, "fs", FS_SINKS)) return;
        const arg = c.arguments?.[0];
        if (!arg) return;
        const argText = arg.getText(ast.source);
        if (sabitYolMi(argText)) return;
        if (!isTainted(ast, arg, index)) return;
        const line = lineNo(ast, c);
        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "high",
          confidence: "likely",
          description:
            "A filesystem path that is not a fixed literal and is tainted by user input is passed to an fs sink. An attacker can traverse directories to read or write arbitrary files.",
          evidence: [fileEvidence(file, line, lineText(ast, c))],
          remediation:
            "Resolve the path against a fixed base directory and verify the result stays inside it (path.normalize + startsWith check), or map user-supplied names to an allowlist.",
        });
      });
    }
    return findings;
  },
};
