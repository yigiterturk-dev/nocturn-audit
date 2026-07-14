import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext } from "../core/rule.js";
import type { StandardsCheck } from "./types.js";
import { apiRouteAuthMissing } from "../static/api-route-auth-missing.js";
import { hardcodedSecrets } from "../static/hardcoded-secrets.js";

/**
 * Nocturn Standartları — GÜVENLİK kontrolleri.
 * Kaynak: feedback_security — rate limit, auth guard, env koruması,
 * güvenlik header'ları, RLS, input validation.
 */

// ---- ortak yardımcılar ------------------------------------------------------

const norm = (f: string): string => f.replace(/\\/g, "/");

const isApiRoute = (file: string): boolean => {
  const f = norm(file);
  return (
    /(^|\/)app\/.*\/route\.(ts|js|tsx|jsx)$/.test(f) ||
    /(^|\/)pages\/api\/.*\.(ts|js|tsx|jsx)$/.test(f)
  );
};

/** Lockfile / üretilmiş json'ları grep dışında tut (FP kaynağı). */
const isSourceFile = (file: string): boolean => {
  const f = norm(file);
  return !/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|.*\.min\.(js|css))$/.test(f);
};

const hasApiRoutes = (ctx: StaticContext): boolean =>
  ctx.files.some(isApiRoute);

/** Sunucu tarafı kod var mı — yoksa rate-limit/auth kontrolleri anlamsız. */
const hasServerSide = (ctx: StaticContext): boolean =>
  hasApiRoutes(ctx) ||
  ctx.project.stack.framework === "node" ||
  ctx.grep(/\bexpress\s*\(\s*\)|createServer\s*\(|\bfastify\s*\(/, isSourceFile).length > 0;

// ---- 1. Rate limit ----------------------------------------------------------

const RATELIMIT_HINT =
  /(@upstash\/ratelimit|express-rate-limit|rate-?limit|rateLimit|Ratelimit|throttle|limiter\b|slowDown|bottleneck|tokenBucket|leakyBucket)/i;

export const stdRateLimit: StandardsCheck = {
  id: "nstd-guv-rate-limit",
  title: "Rate limit altyapısı var",
  category: "guvenlik",
  level: "uyari",
  description:
    "Standart: her projede form/API uçları için rate limiting bulunmalı (brute-force ve kötüye kullanım koruması). Kodda bilinen rate-limit kütüphanesi / middleware izi aranır.",
  remediation:
    "API ve form uçlarına IP+kimlik bazlı rate-limit ekleyin (Next.js için @upstash/ratelimit, Express için express-rate-limit). En azından login/iletişim/ödeme uçlarını kapsayın.",
  run(ctx) {
    if (!hasServerSide(ctx)) {
      return {
        status: "uygulanamaz",
        detail: "Projede API route / sunucu tarafı kod tespit edilmedi — rate limit bu katmanda anlamsız.",
      };
    }
    const hits = ctx.grep(RATELIMIT_HINT, isSourceFile);
    if (hits.length > 0) {
      const h = hits[0];
      return {
        status: "gecti",
        detail: `Rate-limit izi bulundu (${hits.length} eşleşme).`,
        evidence: [fileEvidence(h.file, h.line, h.text)],
      };
    }
    return {
      status: "kaldi",
      detail:
        "Projede hiçbir rate-limit kütüphanesi / middleware izi bulunamadı. API uçları brute-force ve spam'e açık olabilir.",
    };
  },
};

// ---- 2. Auth guard (korumasız API route) ------------------------------------

export const stdAuthGuard: StandardsCheck = {
  id: "nstd-guv-auth-guard",
  title: "API route'ları auth guard'lı",
  category: "guvenlik",
  level: "kritik",
  description:
    "Standart: auth gereken her uçta oturum kontrolü olmalı. Mevcut a01-api-route-auth-missing sezgiselini kullanır — DB'ye dokunan ama auth izi taşımayan route'ları arar.",
  remediation:
    "Handler başında oturum/kullanıcı doğrulaması yapın (Clerk auth(), Supabase getUser(), getServerSession vb.) ve yetkisizse 401/403 dönün. Gerçekten public uçları açıkça belgeleyin.",
  async run(ctx) {
    if (!hasApiRoutes(ctx)) {
      return {
        status: "uygulanamaz",
        detail: "Projede app/api ya da pages/api route'u yok.",
      };
    }
    const findings = (await Promise.resolve(
      apiRouteAuthMissing.run(ctx),
    )) as Finding[];
    if (findings.length === 0) {
      return {
        status: "gecti",
        detail: "DB'ye dokunan tüm API route'larında auth izi bulundu (ya da route'lar bilinen public kalıplarda).",
      };
    }
    const mutations = findings.filter((f) => f.severity === "high");
    const evidence = findings.slice(0, 5).flatMap((f) => f.evidence);
    // Sezgisel kontrol → kesin "kaldı" yerine manuel doğrulama iste (FP koruması).
    if (mutations.length > 0) {
      return {
        status: "manuel",
        detail: `${mutations.length} adet DB'ye YAZAN route'ta auth izi yok (toplam ${findings.length} şüpheli route). Bu uçlar kasıtlı public değilse ciddi açık — elle doğrulayın.`,
        evidence,
      };
    }
    return {
      status: "manuel",
      level: "uyari",
      detail: `${findings.length} adet salt-okuma route'unda auth izi yok. Veri public değilse yetkisiz okumaya açık olabilir — elle doğrulayın.`,
      evidence,
    };
  },
};

// ---- 3. Env koruması ---------------------------------------------------------

export const stdEnvProtection: StandardsCheck = {
  id: "nstd-guv-env-koruma",
  title: ".env koruması (gitignore + commit yok)",
  category: "guvenlik",
  level: "kritik",
  description:
    "Standart: API key'ler her zaman .env + .gitignore; .env asla commit'lenmez. Git izleme durumu ve .gitignore kalıbı kontrol edilir.",
  remediation:
    ".gitignore'a `.env*` (ve `!.env.example`) ekleyin. Commit'lenmiş .env varsa `git rm --cached` ile takipten çıkarın, geçmişi temizleyin ve TÜM sırları yenileyin.",
  run(ctx) {
    const gitignore = ctx.read(".gitignore") ?? "";
    const ignoresEnv = /(^|\n)\s*\.?\*?\.env(\b|\*|\.)/.test(gitignore);

    const envFiles = ctx.files.filter((f) => {
      const base = norm(f).split("/").pop() ?? "";
      return /^\.env/.test(base) && !/\.example|\.sample|\.template/.test(base);
    });

    const tracked = envFiles.filter((f) => {
      const content = ctx.read(f) ?? "";
      const hasRealValue = /^[A-Z0-9_]+\s*=\s*[^\s#][^\n]{6,}/m.test(content);
      return hasRealValue && ctx.isTracked(f);
    });

    if (tracked.length > 0) {
      return {
        status: "kaldi",
        detail: `Gerçek değer içeren ${tracked.length} .env dosyası git tarafından izleniyor (commit'lenmiş): ${tracked.map(norm).join(", ")}. Açık sır sızıntısı.`,
        evidence: tracked.map((f) => fileEvidence(f, 1, "(.env içeriği redakte edildi)")),
      };
    }
    if (!ignoresEnv && ctx.exists("package.json")) {
      return {
        status: "kaldi",
        level: "uyari",
        detail: gitignore
          ? ".gitignore mevcut ama .env kalıbı içermiyor — ileride yanlışlıkla sır commit'lenebilir."
          : ".gitignore dosyası yok — .env dosyaları korumasız.",
        evidence: [fileEvidence(".gitignore", 1, gitignore ? "(.env kalıbı yok)" : "(dosya yok)")],
      };
    }
    if (!ctx.isGitRepo && envFiles.length > 0) {
      return {
        status: "manuel",
        detail: "Proje git deposu değil — .env commit durumu doğrulanamadı. Depo neredeyse orada kontrol edin.",
      };
    }
    return {
      status: "gecti",
      detail: ".gitignore .env kalıbı içeriyor ve izlenen (commit'lenmiş) .env dosyası yok.",
    };
  },
};

// ---- 4. Hardcoded secret -----------------------------------------------------

export const stdHardcodedSecret: StandardsCheck = {
  id: "nstd-guv-hardcoded-secret",
  title: "Kodda gömülü secret yok",
  category: "guvenlik",
  level: "kritik",
  description:
    "Standart: API key/secret asla hardcode edilmez. Mevcut a02-hardcoded-secret kuralına bağlanır (sağlayıcı paternleri + entropi).",
  remediation:
    "Sırları .env'e taşıyın (process.env ile okuyun), açığa çıkan anahtarları sağlayıcı panelinden iptal edip yenileyin.",
  async run(ctx) {
    const findings = (await Promise.resolve(
      hardcodedSecrets.run(ctx),
    )) as Finding[];
    if (findings.length === 0) {
      return { status: "gecti", detail: "Bilinen sağlayıcı paterni ya da yüksek-entropili gömülü sır bulunamadı." };
    }
    const certain = findings.filter((f) => f.confidence !== "olası");
    const evidence = findings.slice(0, 5).flatMap((f) => f.evidence);
    if (certain.length > 0) {
      return {
        status: "kaldi",
        detail: `${certain.length} kesin gömülü sır bulundu (toplam ${findings.length} eşleşme). Bu anahtarlar iptal edilip .env'e taşınmalı.`,
        evidence,
      };
    }
    return {
      status: "manuel",
      detail: `${findings.length} olası gömülü sır eşleşmesi var (entropi sezgiseli) — gerçek sır mı placeholder mı elle doğrulayın.`,
      evidence,
    };
  },
};

// ---- 5. Güvenlik header'ları ---------------------------------------------------

const NEXT_CONFIGS = ["next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs"];
const REQUIRED_HEADERS = [
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Strict-Transport-Security",
  "Referrer-Policy",
];

export const stdSecurityHeaders: StandardsCheck = {
  id: "nstd-guv-headers",
  title: "Güvenlik header'ları tanımlı",
  category: "guvenlik",
  level: "uyari",
  description:
    "Standart: deploy öncesi checklist'te güvenlik header'ları var (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy). next.config ve vercel.json taranır.",
  remediation:
    "next.config headers() içinde (ya da vercel.json \"headers\" bloğunda) CSP, X-Frame-Options: DENY/SAMEORIGIN, X-Content-Type-Options: nosniff, Strict-Transport-Security ve Referrer-Policy tanımlayın.",
  run(ctx) {
    const sources: Array<{ file: string; content: string }> = [];
    for (const f of NEXT_CONFIGS) {
      const c = ctx.read(f);
      if (c != null) sources.push({ file: f, content: c });
    }
    const vercel = ctx.read("vercel.json");
    if (vercel != null) sources.push({ file: "vercel.json", content: vercel });
    // middleware'de de header set edilebilir
    for (const f of ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"]) {
      const c = ctx.read(f);
      if (c != null) sources.push({ file: f, content: c });
    }

    const isNext = ctx.project.stack.framework === "next";
    if (sources.length === 0) {
      if (!isNext) {
        return {
          status: "manuel",
          level: "bilgi",
          detail:
            "next.config / vercel.json / middleware bulunamadı. Header'lar hosting katmanında (Cloudflare, nginx) ayarlanmış olabilir — elle doğrulayın.",
        };
      }
      return {
        status: "kaldi",
        detail: "Next.js projesi ama header tanımlanabilecek hiçbir konfigürasyon dosyası yok (next.config / vercel.json / middleware).",
      };
    }

    const combined = sources.map((s) => s.content).join("\n");
    const missing = REQUIRED_HEADERS.filter(
      (h) => !new RegExp(h, "i").test(combined),
    );
    if (missing.length === 0) {
      return {
        status: "gecti",
        detail: `Beklenen güvenlik header'larının tümü tanımlı (${sources.map((s) => s.file).join(", ")}).`,
      };
    }
    if (missing.length === REQUIRED_HEADERS.length) {
      return {
        status: "kaldi",
        detail: `Hiçbir güvenlik header'ı tanımlı değil (bakılan: ${sources.map((s) => s.file).join(", ")}).`,
        evidence: [fileEvidence(sources[0].file, 1, "(güvenlik header'ı yok)")],
      };
    }
    return {
      status: "kaldi",
      level: "bilgi",
      detail: `Eksik header'lar: ${missing.join(", ")} (bakılan: ${sources.map((s) => s.file).join(", ")}).`,
      evidence: [fileEvidence(sources[0].file, 1, `eksik: ${missing.join(", ")}`)],
    };
  },
};

// ---- 6. Supabase RLS ----------------------------------------------------------

export const stdSupabaseRls: StandardsCheck = {
  id: "nstd-guv-rls",
  title: "Supabase RLS politikaları tanımlı",
  category: "guvenlik",
  level: "uyari",
  description:
    "Standart: Supabase kullanan projede RLS ile veri izolasyonu şart. Migration/SQL dosyalarında ENABLE ROW LEVEL SECURITY / CREATE POLICY izleri aranır (sezgisel — politikalar yalnızca dashboard'da olabilir).",
  remediation:
    "Her tabloda `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;` + uygun `CREATE POLICY` tanımlayın ve bunları migration dosyası olarak repoya alın (dashboard'da kalmasın).",
  run(ctx) {
    if (ctx.project.stack.db !== "supabase") {
      return { status: "uygulanamaz", detail: "Proje Supabase kullanmıyor." };
    }
    const hits = ctx.grep(
      /(ENABLE\s+ROW\s+LEVEL\s+SECURITY|CREATE\s+POLICY)/i,
      (f) => /\.(sql|md|mdx)$/i.test(f) && isSourceFile(f),
    );
    if (hits.length > 0) {
      const h = hits[0];
      return {
        status: "gecti",
        detail: `RLS izi bulundu (${hits.length} eşleşme) — politikaların TÜM tabloları kapsadığını yine de doğrulayın.`,
        evidence: [fileEvidence(h.file, h.line, h.text)],
      };
    }
    return {
      status: "manuel",
      detail:
        "Repoda RLS politikası izi yok. Politikalar Supabase dashboard'da tanımlı olabilir — dashboard'dan tablo tablo doğrulayın; yoksa tüm veriler anon anahtarla okunabilir demektir.",
    };
  },
};

// ---- 7. Input validation --------------------------------------------------------

const VALIDATION_HINT =
  /(\bzod\b|z\.object\(|\.safeParse\(|zodResolver|\byup\b|yup\.|joi\.|\bjoi\b|valibot|class-validator|express-validator)/;

export const stdInputValidation: StandardsCheck = {
  id: "nstd-guv-input-validation",
  title: "Input validation altyapısı var",
  category: "guvenlik",
  level: "bilgi",
  description:
    "Standart: her system boundary'de input validation. Bilinen şema doğrulama kütüphanesi izi aranır (zod/yup/joi/valibot) — kullanımın her uca uygulandığını kanıtlamaz.",
  remediation:
    "API route ve form handler'larında zod gibi bir şema doğrulayıcı kullanın (`schema.safeParse(body)`), doğrulanmamış body'yi asla DB'ye geçirmeyin.",
  run(ctx) {
    if (!hasServerSide(ctx)) {
      return { status: "uygulanamaz", detail: "Sunucu tarafı kod yok — bu katmanda input validation aranmaz." };
    }
    const pkg = ctx.read("package.json") ?? "";
    const inDeps = /"(zod|yup|joi|valibot|class-validator|express-validator)"\s*:/.test(pkg);
    const hits = ctx.grep(VALIDATION_HINT, (f) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f) && isSourceFile(f));
    if (inDeps || hits.length > 0) {
      const ev = hits[0]
        ? [fileEvidence(hits[0].file, hits[0].line, hits[0].text)]
        : [fileEvidence("package.json", 1, "(bağımlılıklarda doğrulama kütüphanesi)")];
      return {
        status: "gecti",
        detail: `Şema doğrulama izi bulundu${hits.length ? ` (${hits.length} eşleşme)` : " (package.json)"} — her uçta kullanıldığını kod incelemesiyle doğrulayın.`,
        evidence: ev,
      };
    }
    return {
      status: "manuel",
      detail:
        "Bilinen bir şema doğrulama kütüphanesi izi yok. Elle doğrulama yapılıyor olabilir — API uçlarındaki body işleme kodunu gözden geçirin.",
    };
  },
};

export const securityChecks: StandardsCheck[] = [
  stdRateLimit,
  stdAuthGuard,
  stdEnvProtection,
  stdHardcodedSecret,
  stdSecurityHeaders,
  stdSupabaseRls,
  stdInputValidation,
];
