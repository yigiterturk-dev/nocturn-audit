import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { runStandards, standardsChecks } from "../src/standards/index.js";
import {
  stdAuthGuard,
  stdEnvProtection,
  stdHardcodedSecret,
  stdInputValidation,
  stdRateLimit,
  stdSecurityHeaders,
  stdSupabaseRls,
} from "../src/standards/security.js";
import {
  stdLoadingSkeleton,
  stdSelectStar,
  stdSequentialAwait,
  stdVercelRegion,
} from "../src/standards/performance.js";

const API_ROUTE = `export async function POST(req){ const b = await req.json(); await db.orders.create({ data: b }); return Response.json({ok:true}); }`;

describe("nstd-guv-rate-limit", () => {
  it("API route var + rate-limit izi yok → kaldı", async () => {
    const r = await stdRateLimit.run(makeCtx({ "app/api/orders/route.ts": API_ROUTE }));
    expect(r.status).toBe("kaldi");
  });
  it("@upstash/ratelimit izi → geçti", async () => {
    const r = await stdRateLimit.run(
      makeCtx({
        "app/api/orders/route.ts": API_ROUTE,
        "lib/ratelimit.ts": `import { Ratelimit } from "@upstash/ratelimit";`,
      }),
    );
    expect(r.status).toBe("gecti");
  });
  it("sunucu tarafı kod yoksa → uygulanamaz", async () => {
    const r = await stdRateLimit.run(
      makeCtx({ "src/App.tsx": "export default () => <div/>" }, { stack: { framework: "vite" } }),
    );
    expect(r.status).toBe("uygulanamaz");
  });
  it("package-lock.json'daki eşleşme sayılmaz (FP koruması)", async () => {
    const r = await stdRateLimit.run(
      makeCtx({
        "app/api/orders/route.ts": API_ROUTE,
        "package-lock.json": `"express-rate-limit": "7.0.0"`,
      }),
    );
    expect(r.status).toBe("kaldi");
  });
});

describe("nstd-guv-auth-guard", () => {
  it("auth'suz mutation route → MANUEL (kritik) — sezgisel, asla kesin kaldı değil", async () => {
    const r = await stdAuthGuard.run(makeCtx({ "app/api/orders/route.ts": API_ROUTE }));
    expect(r.status).toBe("manuel");
    expect(r.level ?? "kritik").toBe("kritik");
  });
  it("auth'lu route → geçti", async () => {
    const r = await stdAuthGuard.run(
      makeCtx({
        "app/api/orders/route.ts": `import { auth } from "@clerk/nextjs"; export async function POST(req){ const { userId } = auth(); if(!userId) return new Response("401",{status:401}); await db.orders.create({}); }`,
      }),
    );
    expect(r.status).toBe("gecti");
  });
  it("API route yoksa → uygulanamaz", async () => {
    const r = await stdAuthGuard.run(makeCtx({ "src/index.ts": "console.log(1)" }));
    expect(r.status).toBe("uygulanamaz");
  });
});

describe("nstd-guv-env-koruma", () => {
  it("commit'lenmiş gerçek .env → kaldı (kritik)", async () => {
    const r = await stdEnvProtection.run(
      makeCtx(
        { ".env": "DATABASE_URL=postgres://user:pass@host/db", "package.json": "{}" },
        { tracked: [".env", "package.json"] },
      ),
    );
    expect(r.status).toBe("kaldi");
    expect(r.level ?? "kritik").toBe("kritik");
  });
  it("gitignore'lanmış .env + kalıp var → geçti", async () => {
    const r = await stdEnvProtection.run(
      makeCtx(
        { ".env": "DATABASE_URL=postgres://user:pass@host/db", ".gitignore": ".env*\n", "package.json": "{}" },
        { tracked: [".gitignore", "package.json"] },
      ),
    );
    expect(r.status).toBe("gecti");
  });
  it(".gitignore .env kalıbı içermiyor → kaldı (uyarı)", async () => {
    const r = await stdEnvProtection.run(
      makeCtx({ ".gitignore": "node_modules\n", "package.json": "{}" }, { tracked: [".gitignore", "package.json"] }),
    );
    expect(r.status).toBe("kaldi");
    expect(r.level).toBe("uyari");
  });
});

describe("nstd-guv-hardcoded-secret", () => {
  it("Stripe live key → kaldı", async () => {
    const r = await stdHardcodedSecret.run(
      makeCtx({ "lib/pay.ts": `const key = "sk_live_${"a1B2c3D4e5F6g7H8"}";` }),
    );
    expect(r.status).toBe("kaldi");
  });
  it("temiz kod → geçti", async () => {
    const r = await stdHardcodedSecret.run(
      makeCtx({ "lib/pay.ts": `const key = process.env.STRIPE_KEY;` }),
    );
    expect(r.status).toBe("gecti");
  });
});

describe("nstd-guv-headers", () => {
  it("Next projesi, hiç config yok → kaldı", async () => {
    const r = await stdSecurityHeaders.run(makeCtx({ "package.json": "{}" }));
    expect(r.status).toBe("kaldi");
  });
  it("tüm header'lar next.config'te → geçti", async () => {
    const r = await stdSecurityHeaders.run(
      makeCtx({
        "next.config.js": `headers: Content-Security-Policy X-Frame-Options X-Content-Type-Options Strict-Transport-Security Referrer-Policy`,
      }),
    );
    expect(r.status).toBe("gecti");
  });
  it("kısmi header → kaldı (bilgi) — eksikler listelenir", async () => {
    const r = await stdSecurityHeaders.run(
      makeCtx({ "next.config.js": `X-Frame-Options X-Content-Type-Options` }),
    );
    expect(r.status).toBe("kaldi");
    expect(r.level).toBe("bilgi");
    expect(r.detail).toContain("Content-Security-Policy");
  });
});

describe("nstd-guv-rls", () => {
  it("Supabase + migration'da CREATE POLICY → geçti", async () => {
    const r = await stdSupabaseRls.run(
      makeCtx({ "supabase/migrations/001.sql": "ALTER TABLE x ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON x;" }),
    );
    expect(r.status).toBe("gecti");
  });
  it("Supabase ama repoda RLS izi yok → manuel (dashboard'da olabilir)", async () => {
    const r = await stdSupabaseRls.run(makeCtx({ "lib/db.ts": "supabase.from('x')" }));
    expect(r.status).toBe("manuel");
  });
  it("Supabase değil → uygulanamaz", async () => {
    const r = await stdSupabaseRls.run(makeCtx({}, { stack: { db: "postgres" } }));
    expect(r.status).toBe("uygulanamaz");
  });
});

describe("nstd-guv-input-validation", () => {
  it("zod deps'te → geçti", async () => {
    const r = await stdInputValidation.run(
      makeCtx({ "package.json": `{"dependencies":{"zod":"^3.0.0"}}`, "app/api/x/route.ts": API_ROUTE }),
    );
    expect(r.status).toBe("gecti");
  });
  it("API var, doğrulama izi yok → manuel", async () => {
    const r = await stdInputValidation.run(
      makeCtx({ "package.json": "{}", "app/api/x/route.ts": API_ROUTE }),
    );
    expect(r.status).toBe("manuel");
  });
});

describe("nstd-hiz-bolge", () => {
  it("regions tanımlı → geçti (DB uyumu manuel notuyla)", async () => {
    const r = await stdVercelRegion.run(makeCtx({ "vercel.json": `{"regions":["fra1"]}` }));
    expect(r.status).toBe("gecti");
    expect(r.detail).toContain("manuel");
  });
  it("vercel.json var, regions yok → kaldı", async () => {
    const r = await stdVercelRegion.run(makeCtx({ "vercel.json": `{}` }));
    expect(r.status).toBe("kaldi");
  });
  it("vercel.json yok → manuel (Vercel'de olmayabilir)", async () => {
    const r = await stdVercelRegion.run(makeCtx({ "package.json": "{}" }));
    expect(r.status).toBe("manuel");
  });
});

describe("nstd-hiz-ardisik-await", () => {
  const manyAwaits = Array.from({ length: 6 }, (_, i) => `const x${i} = await q${i}();`).join("\n");
  it("6 await + Promise.all yok → manuel (sezgisel)", async () => {
    const r = await stdSequentialAwait.run(makeCtx({ "app/dashboard/page.tsx": manyAwaits }));
    expect(r.status).toBe("manuel");
  });
  it("Promise.all kullanılıyor → geçti", async () => {
    const r = await stdSequentialAwait.run(
      makeCtx({ "app/dashboard/page.tsx": manyAwaits + "\nawait Promise.all([a,b]);" }),
    );
    expect(r.status).toBe("gecti");
  });
});

describe("nstd-hiz-loading", () => {
  it("app router + hiç loading.tsx yok → kaldı", async () => {
    const r = await stdLoadingSkeleton.run(makeCtx({ "app/page.tsx": "export default function P(){}" }));
    expect(r.status).toBe("kaldi");
  });
  it("loading.tsx var → geçti", async () => {
    const r = await stdLoadingSkeleton.run(
      makeCtx({ "app/page.tsx": "x", "app/loading.tsx": "export default function L(){}" }),
    );
    expect(r.status).toBe("gecti");
  });
  it("Next app router değil → uygulanamaz", async () => {
    const r = await stdLoadingSkeleton.run(
      makeCtx({ "src/App.tsx": "x" }, { stack: { framework: "vite" } }),
    );
    expect(r.status).toBe("uygulanamaz");
  });
});

describe("nstd-hiz-select-star", () => {
  it(".select('*') → kaldı (bilgi)", async () => {
    const r = await stdSelectStar.run(
      makeCtx({ "lib/db.ts": `const { data } = await supabase.from("orders").select("*");` }),
    );
    expect(r.status).toBe("kaldi");
  });
  it("daraltılmış select → geçti", async () => {
    const r = await stdSelectStar.run(
      makeCtx({ "lib/db.ts": `const { data } = await supabase.from("orders").select("id, name");` }),
    );
    expect(r.status).toBe("gecti");
  });
});

describe("runStandards (profil bütünü)", () => {
  it("her kontrol için bir sonuç üretir + skor/kategori kırılımı doğru", async () => {
    const ctx = makeCtx({
      "app/api/orders/route.ts": API_ROUTE,
      ".gitignore": ".env*\n",
      "package.json": "{}",
    });
    const res = await runStandards(ctx);
    expect(res.profile).toBe("nocturn-standards");
    expect(res.checks.length).toBe(standardsChecks.length);
    expect(res.categories.guvenlik.score).toBeLessThanOrEqual(100);
    expect(res.categories.hiz.score).toBeLessThanOrEqual(100);
    const sum =
      res.counts.gecti + res.counts.kaldi + res.counts.manuel + res.counts.uygulanamaz;
    expect(sum).toBe(standardsChecks.length);
    // rate-limit kaldı (uyarı −10) skoru düşürmeli
    const rl = res.checks.find((c) => c.id === "nstd-guv-rate-limit");
    expect(rl?.status).toBe("kaldi");
    expect(res.categories.guvenlik.score).toBeLessThan(100);
    // manuel sonuçlar ceza almaz: yalnızca kaldı'lar skoru düşürür
    const failPenalty = res.checks
      .filter((c) => c.status === "kaldi")
      .reduce((n, c) => n + (c.level === "kritik" ? 25 : c.level === "uyari" ? 10 : 3), 0);
    expect(res.score).toBe(Math.max(0, 100 - failPenalty));
  });
});
