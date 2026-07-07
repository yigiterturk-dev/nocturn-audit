import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A05 — Build / yapılandırma sağlığı (statik, sezgisel).
 *
 * Ağır araç ÇALIŞTIRMADAN (tsc/build yok) yalnızca statik sezgiler:
 *  1) Kodda kullanılan ama `.env.example`/`.env*`'de tanımsız env değişkenleri.
 *  2) TS `strict` kapalı (info).
 *  3) next/vite projesinde `build` script'i yok (low).
 *  4) Var olmayan dosyaya relative import (best-effort, düşük/olası, tavanlı).
 *
 * Kesin bir açık değil; operasyonel/config sağlığı → düşük severity + olası.
 */

/** Framework/host tarafından sağlanan, .env.example'da beklenmeyen env değişkenleri. */
const BUILTIN_ENV = new Set([
  "NODE_ENV",
  "NODE_OPTIONS",
  "NEXT_RUNTIME",
  "NEXT_PHASE",
  "NEXT_PUBLIC_VERCEL_URL",
  "NEXT_PUBLIC_VERCEL_ENV",
  "VERCEL",
  "VERCEL_URL",
  "VERCEL_ENV",
  "VERCEL_REGION",
  "VERCEL_GIT_COMMIT_SHA",
  "CI",
  "PORT",
  "HOST",
  "HOSTNAME",
  "PWD",
  "HOME",
  "PATH",
  "TZ",
  "LANG",
  "SHELL",
  "USER",
  "ANALYZE",
  "npm_package_version",
  "npm_lifecycle_event",
]);

const ENV_FILE_RE = /(^|[/\\])\.env(\.[\w.-]+)?$/;
const SOURCE_CODE = (f: string): boolean =>
  /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f) && !ENV_FILE_RE.test(f);

/** Kodda referans verilen env anahtarlarını topla (dosya-bazlı, tüm eşleşmeler). */
function referencedEnvKeys(ctx: StaticContext): Map<string, { file: string; line: number }> {
  const keys = new Map<string, { file: string; line: number }>();
  const re = /(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,})\b/g;
  for (const file of ctx.files) {
    if (!SOURCE_CODE(file)) continue;
    const content = ctx.read(file);
    if (content == null) continue;
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(lines[i])) !== null) {
        const key = m[1];
        if (key && !keys.has(key)) keys.set(key, { file, line: i + 1 });
      }
    }
  }
  return keys;
}

/** .env.example / .env* dosyalarında tanımlı anahtarlar. */
function definedEnvKeys(ctx: StaticContext): { keys: Set<string>; hasExample: boolean } {
  const keys = new Set<string>();
  let hasExample = false;
  const envFiles = ctx.files.filter((f) => {
    const base = f.replace(/\\/g, "/").split("/").pop() ?? "";
    return /^\.env/.test(base);
  });
  for (const f of envFiles) {
    const base = (f.replace(/\\/g, "/").split("/").pop() ?? "");
    if (/\.(example|sample|template)$/.test(base)) hasExample = true;
    const content = ctx.read(f) ?? "";
    for (const line of content.split(/\r?\n/)) {
      const km = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=/.exec(line);
      if (km) keys.add(km[1]);
    }
  }
  return { keys, hasExample };
}

const ASSET_EXT = /\.(css|scss|sass|less|styl|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|mp[34]|webm|wasm|md|txt|graphql|gql|yml|yaml|xml|csv|glb|gltf)$/i;

/** relative import var-mı diye best-effort çözümle. */
function resolvesTo(files: Set<string>, importer: string, spec: string): boolean {
  const dir = importer.replace(/\\/g, "/").split("/").slice(0, -1);
  const parts = spec.split("/");
  const stack = [...dir];
  for (const p of parts) {
    if (p === "." || p === "") continue;
    if (p === "..") stack.pop();
    else stack.push(p);
  }
  const base = stack.join("/");
  const cands = [
    base,
    // .js/.jsx belirtilmiş ama TS kaynağı olabilir (NodeNext ESM stili)
    base.replace(/\.jsx?$/, ".ts"),
    base.replace(/\.jsx?$/, ".tsx"),
  ];
  const exts = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json"];
  const idx = ["/index.ts", "/index.tsx", "/index.js", "/index.jsx"];
  for (const c of cands) {
    for (const e of exts) if (files.has(c + e)) return true;
    for (const i of idx) if (files.has(c + i)) return true;
  }
  return false;
}

const MAX_BROKEN_IMPORTS = 8;

export const buildConfig: StaticRule = {
  id: "a05-build-config-health",
  title: "Build / yapılandırma sağlığı",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "low",
  kind: "static",
  confidence: "olası",
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // --- 1) Kodda kullanılan ama tanımsız env değişkenleri ---
    const referenced = referencedEnvKeys(ctx);
    const { keys: defined, hasExample } = definedEnvKeys(ctx);
    const undocumented: string[] = [];
    for (const [key, loc] of referenced) {
      if (BUILTIN_ENV.has(key)) continue;
      if (defined.has(key)) continue;
      undocumented.push(`${key} (${loc.file}:${loc.line})`);
    }
    if (undocumented.length > 0) {
      const list = undocumented.slice(0, 20);
      if (hasExample) {
        const sample = referenced.get(undocumented[0].split(" ")[0]);
        findings.push({
          ruleId: this.id,
          title: `Env değişkeni kodda kullanılıyor ama .env.example'da tanımsız (${undocumented.length})`,
          owasp: this.owasp,
          severity: "low",
          confidence: "olası",
          description: `Kod ${undocumented.length} adet env değişkenine referans veriyor ama bunlar .env.example / .env* içinde tanımlı değil. Deploy'da eksik env yüzünden çalışma zamanı hataları veya sessiz yanlış davranış oluşabilir. Örnekler: ${list.join(", ")}${undocumented.length > 20 ? " …" : ""}`,
          evidence: [
            fileEvidence(sample?.file ?? ".env.example", sample?.line ?? 1, list[0]),
          ],
          remediation:
            ".env.example dosyasına bu anahtarları (değersiz/placeholder) ekleyin; böylece deploy ortamında hangi env'lerin gerektiği belgelenir.",
        });
      } else if (undocumented.length >= 5) {
        // Hiç .env.example yok ama kod env'e bağımlı → tek bilgi notu.
        findings.push({
          ruleId: this.id,
          title: `.env.example yok ama kod ${undocumented.length} env değişkenine bağımlı`,
          owasp: this.owasp,
          severity: "info",
          confidence: "olası",
          description: `Projede .env.example bulunamadı, ancak kod ${undocumented.length} env değişkenine referans veriyor. Gerekli env'ler belgelenmediği için yeni ortama deploy sırasında eksik değişkenler gözden kaçabilir. Örnekler: ${list.slice(0, 10).join(", ")}`,
          evidence: [fileEvidence("package.json", 1, "(.env.example yok)")],
          remediation:
            "Gerekli env anahtarlarını içeren bir .env.example ekleyin (gerçek değer koymadan).",
        });
      }
    }

    // --- 2) TypeScript strict kapalı ---
    const tsconfigFile = ["tsconfig.json"].find((f) => ctx.exists(f));
    if (tsconfigFile) {
      const raw = ctx.read(tsconfigFile) ?? "";
      // Yorumları kaba temizle (tsconfig JSONC olabilir).
      if (/"strict"\s*:\s*false/.test(raw)) {
        findings.push({
          ruleId: this.id,
          title: "TypeScript strict modu kapalı",
          owasp: this.owasp,
          severity: "info",
          confidence: "olası",
          description:
            "tsconfig.json içinde \"strict\": false tanımlı. Strict mod kapalıyken null/undefined ve tip hataları derlemede yakalanmaz; çalışma zamanı hataları ve güvenlik açıkları (ör. doğrulanmamış girdi) gözden kaçabilir.",
          evidence: [fileEvidence(tsconfigFile, 1, '"strict": false')],
          remediation:
            'tsconfig.json compilerOptions içinde "strict": true yapın; ortaya çıkan tip hatalarını giderin.',
        });
      }
    }

    // --- 3) next/vite projesinde build script yok ---
    const fw = ctx.project.stack.framework;
    if ((fw === "next" || fw === "vite") && ctx.exists("package.json")) {
      try {
        const pkg = JSON.parse(ctx.read("package.json") ?? "{}") as {
          scripts?: Record<string, string>;
        };
        const scripts = pkg.scripts ?? {};
        if (!scripts.build) {
          findings.push({
            ruleId: this.id,
            title: "package.json'da build script'i yok",
            owasp: this.owasp,
            severity: "low",
            confidence: "olası",
            description: `${fw} projesi ama package.json scripts içinde "build" tanımı yok. Üretim derlemesi/deploy adımı belirsiz; CI/CD veya hosting build'i başarısız olabilir.`,
            evidence: [fileEvidence("package.json", 1, "(scripts.build yok)")],
            remediation: `scripts içine "build": "${fw === "next" ? "next build" : "vite build"}" ekleyin.`,
          });
        }
      } catch {
        /* package.json parse edilemedi → yoksay */
      }
    }

    // --- 4) Var olmayan dosyaya relative import (best-effort, tavanlı) ---
    const fileSet = new Set(ctx.files.map((f) => f.replace(/\\/g, "/")));
    const importRe = /(?:import|export)[^'"]*?from\s*['"](\.\.?\/[^'"]+)['"]|(?:require|import)\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/;
    const broken: { file: string; line: number; spec: string }[] = [];
    const seen = new Set<string>();
    outer: for (const m of ctx.grep(importRe, SOURCE_CODE)) {
      const mm = new RegExp(importRe.source).exec(m.text);
      const rawSpec = mm?.[1] ?? mm?.[2];
      if (!rawSpec) continue;
      // ?query / #hash soneklerini at (ör. ./x.wasm?module, ./y.css?inline)
      const spec = rawSpec.replace(/[?#].*$/, "");
      if (ASSET_EXT.test(spec)) continue; // css/görsel/wasm vb. taranmıyor → atla
      const importer = m.file.replace(/\\/g, "/");
      if (resolvesTo(fileSet, importer, spec)) continue;
      const key = `${importer}:${spec}`;
      if (seen.has(key)) continue;
      seen.add(key);
      broken.push({ file: m.file, line: m.line, spec });
      if (broken.length >= MAX_BROKEN_IMPORTS) break outer;
    }
    for (const b of broken) {
      findings.push({
        ruleId: this.id,
        title: `Çözülemeyen relative import: ${b.spec}`,
        owasp: this.owasp,
        severity: "low",
        confidence: "olası",
        description: `${b.file}:${b.line} → "${b.spec}" hedefi projede bulunamadı (dosya taşınmış/silinmiş veya yanlış yol olabilir). Build kırılabilir. Not: path-alias (@/...) çözümleyicisi kapsam dışı; yalnızca ./ ve ../ importları kontrol edilir.`,
        evidence: [fileEvidence(b.file, b.line, b.spec)],
        remediation: "Import yolunu düzeltin veya eksik dosyayı geri ekleyin.",
      });
    }

    return findings;
  },
};
