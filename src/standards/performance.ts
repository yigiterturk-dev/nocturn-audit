import { fileEvidence } from "../core/finding.js";
import type { StaticContext } from "../core/rule.js";
import type { StandardsCheck } from "./types.js";

/**
 * Nocturn Standartları — HIZ kontrolleri.
 * Kaynak: feedback_hiz_standardi (crm-v2 vakası: iad1 + eu-west-1 + ardışık
 * sorgular → 1.47s TTFB; düzeltmeyle 0.26s):
 * bölge hizalama, ardışık sorgu avı, loading.tsx iskeletleri, select * daraltma.
 */

const norm = (f: string): string => f.replace(/\\/g, "/");

/** Lockfile / üretilmiş dosyaları dışla. */
const isSourceFile = (file: string): boolean => {
  const f = norm(file);
  return !/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|.*\.min\.(js|css))$/.test(f);
};

const appPageFiles = (ctx: StaticContext): string[] =>
  ctx.files.filter((f) => /(^|\/)app\/(.*\/)?page\.(tsx|jsx|ts|js)$/.test(norm(f)));

// ---- 1. Vercel bölge hizalama ------------------------------------------------

export const stdVercelRegion: StandardsCheck = {
  id: "nstd-hiz-bolge",
  title: "Vercel bölgesi sabitlenmiş (DB ile hizalı)",
  category: "hiz",
  level: "uyari",
  description:
    "Standart: Vercel functions bölgesi = DB bölgesi (her uzak tur ~80ms+). vercel.json'da \"regions\" ayarı aranır. DB bölgesi statik olarak tespit edilemez — uyum manuel doğrulanır.",
  remediation:
    'vercel.json\'a `"regions": ["fra1"]` gibi DB\'nizle aynı bölgeyi ekleyin (Supabase eu-central → fra1/dub1, us-east → iad1). Supabase projesinin bölgesini dashboard\'dan kontrol edin.',
  run(ctx) {
    const raw = ctx.read("vercel.json");
    if (raw == null) {
      return {
        status: "manuel",
        detail:
          "vercel.json yok. Proje Vercel'de yayındaysa functions varsayılan bölgede (iad1) çalışır — DB Avrupa'daysa her sorgu okyanus aşar. Vercel'de değilse yoksayın.",
      };
    }
    let regions: unknown;
    try {
      regions = (JSON.parse(raw) as Record<string, unknown>).regions;
    } catch {
      regions = undefined;
    }
    if (Array.isArray(regions) && regions.length > 0) {
      return {
        status: "gecti",
        detail: `Bölge sabitlenmiş: ${regions.join(", ")}. DB bölgesiyle uyumu manuel doğrulayın (statik tespit edilemez).`,
        evidence: [fileEvidence("vercel.json", 1, `"regions": ${JSON.stringify(regions)}`)],
      };
    }
    return {
      status: "kaldi",
      detail:
        "vercel.json var ama \"regions\" tanımlı değil — functions varsayılan bölgede (iad1) çalışır. DB başka bölgedeyse her sorguya ~80ms+ eklenir.",
      evidence: [fileEvidence("vercel.json", 1, '("regions" alanı yok)')],
    };
  },
};

// ---- 2. Ardışık await zinciri (sezgisel) --------------------------------------

const AWAIT_THRESHOLD = 5;

export const stdSequentialAwait: StandardsCheck = {
  id: "nstd-hiz-ardisik-await",
  title: "Sayfa başına ardışık sorgu zinciri yok",
  category: "hiz",
  level: "bilgi",
  description:
    `Standart: bağımsız sorgular Promise.all'a — sayfa = 1 paralel batch. Sezgisel: bir sayfa/route dosyasında ≥${AWAIT_THRESHOLD} await olup hiç Promise.all yoksa şüpheli sayılır (kesin değil — await'ler bağımlı olabilir).`,
  remediation:
    "Sayfadaki await zincirini sayın; birbirinden bağımsız sorguları `const [a, b, c] = await Promise.all([...])` ile paralelleştirin. Tekrarlanan auth/rol sorgularını React cache() ile teke indirin. Fix'i TTFB ölçümüyle kanıtlayın.",
  run(ctx) {
    const targets = ctx.files.filter((f) => {
      const n = norm(f);
      return (
        /(^|\/)app\/.*\/(page|layout|route)\.(tsx|jsx|ts|js)$/.test(n) ||
        /(^|\/)app\/(page|layout)\.(tsx|jsx|ts|js)$/.test(n) ||
        /(^|\/)pages\/.*\.(tsx|jsx|ts|js)$/.test(n)
      );
    });
    if (targets.length === 0) {
      return { status: "uygulanamaz", detail: "Sayfa/route dosyası bulunamadı (Next.js app/pages yapısı yok)." };
    }
    const suspects: Array<{ file: string; awaits: number; line: number }> = [];
    for (const file of targets) {
      const content = ctx.read(file);
      if (!content) continue;
      const awaits = (content.match(/\bawait\s/g) ?? []).length;
      if (awaits >= AWAIT_THRESHOLD && !/Promise\.all(Settled)?\s*\(/.test(content)) {
        const line = content.split(/\r?\n/).findIndex((l) => /\bawait\s/.test(l)) + 1;
        suspects.push({ file, awaits, line: Math.max(1, line) });
      }
    }
    if (suspects.length === 0) {
      return {
        status: "gecti",
        detail: `${targets.length} sayfa/route dosyasında şüpheli ardışık await zinciri yok (eşik: ${AWAIT_THRESHOLD}, Promise.all'sız).`,
      };
    }
    suspects.sort((a, b) => b.awaits - a.awaits);
    return {
      status: "manuel",
      detail:
        `${suspects.length} dosyada ≥${AWAIT_THRESHOLD} await var ve hiç Promise.all yok: ` +
        suspects.slice(0, 5).map((s) => `${norm(s.file)} (${s.awaits} await)`).join(", ") +
        ". Await'ler bağımsızsa paralelleştirin — bağımlıysa yoksayın (sezgisel kontrol).",
      evidence: suspects.slice(0, 5).map((s) => fileEvidence(s.file, s.line, `${s.awaits} await, Promise.all yok`)),
    };
  },
};

// ---- 3. loading.tsx iskeletleri -----------------------------------------------

export const stdLoadingSkeleton: StandardsCheck = {
  id: "nstd-hiz-loading",
  title: "loading.tsx iskeletleri var",
  category: "hiz",
  level: "uyari",
  description:
    "Standart: her rotada loading.tsx iskeleti — algılanan hız, beyaz ekran yasak. Next.js app router projesinde loading dosyası sayısı kontrol edilir.",
  remediation:
    "app/ altında (en azından kök ve veri çeken rota gruplarında) loading.tsx ekleyip iskelet (skeleton) gösterin — Suspense sınırı otomatik kurulur.",
  run(ctx) {
    const pages = appPageFiles(ctx);
    if (ctx.project.stack.framework !== "next" || pages.length === 0) {
      return { status: "uygulanamaz", detail: "Next.js app router yapısı tespit edilmedi." };
    }
    const loadings = ctx.files.filter((f) => /(^|\/)app\/(.*\/)?loading\.(tsx|jsx|ts|js)$/.test(norm(f)));
    if (loadings.length === 0) {
      return {
        status: "kaldi",
        detail: `app router'da ${pages.length} sayfa var ama hiç loading.tsx yok — sunucu sorguları sürerken kullanıcı beyaz ekran görür.`,
        evidence: [fileEvidence("app/loading.tsx", 1, "(dosya yok)")],
      };
    }
    return {
      status: "gecti",
      detail: `${loadings.length} loading dosyası bulundu (${pages.length} sayfa). Veri çeken tüm rota gruplarını kapsadığını kontrol edin.`,
      evidence: [fileEvidence(loadings[0], 1, norm(loadings[0]))],
    };
  },
};

// ---- 4. select * daraltma ------------------------------------------------------

const SELECT_STAR =
  /\.select\(\s*["'`]\*["'`]\s*\)|\bSELECT\s+\*\s+FROM\b/i;

export const stdSelectStar: StandardsCheck = {
  id: "nstd-hiz-select-star",
  title: "Ağır listelerde select * yok",
  category: "hiz",
  level: "bilgi",
  description:
    "Standart: ağır listelerde `select *` daraltılır; sayaçlar head+count ile alınır. Kodda .select('*') ve SQL SELECT * kullanımları aranır.",
  remediation:
    "Sadece ihtiyaç duyulan kolonları seçin: `.select(\"id, name, created_at\")`. Satır saymak için `select(\"*\", { count: \"exact\", head: true })` kullanın.",
  run(ctx) {
    const hits = ctx.grep(SELECT_STAR, (f) => /\.(ts|tsx|js|jsx|mjs|cjs|sql)$/.test(f) && isSourceFile(norm(f)));
    if (hits.length === 0) {
      return { status: "gecti", detail: "select('*') / SELECT * kullanımı bulunamadı." };
    }
    return {
      status: "kaldi",
      detail: `${hits.length} yerde select * kullanılıyor. Küçük tablolarda sorun değil — ağır liste sorgularındakileri daraltın.`,
      evidence: hits.slice(0, 5).map((h) => fileEvidence(h.file, h.line, h.text)),
    };
  },
};

export const performanceChecks: StandardsCheck[] = [
  stdVercelRegion,
  stdSequentialAwait,
  stdLoadingSkeleton,
  stdSelectStar,
];
