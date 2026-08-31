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

describe("std-sec-rate-limit", () => {
  it("an API route exists with no rate-limit signal → open", async () => {
    const r = await stdRateLimit.run(makeCtx({ "app/api/orders/route.ts": API_ROUTE }));
    expect(r.status).toBe("open");
  });
  it("an @upstash/ratelimit signal → pass", async () => {
    const r = await stdRateLimit.run(
      makeCtx({
        "app/api/orders/route.ts": API_ROUTE,
        "lib/ratelimit.ts": `import { Ratelimit } from "@upstash/ratelimit";`,
      }),
    );
    expect(r.status).toBe("pass");
  });
  it("no server-side code → na", async () => {
    const r = await stdRateLimit.run(
      makeCtx({ "src/App.tsx": "export default () => <div/>" }, { stack: { framework: "vite" } }),
    );
    expect(r.status).toBe("na");
  });
  it("a match in package-lock.json does not count (FP guard)", async () => {
    const r = await stdRateLimit.run(
      makeCtx({
        "app/api/orders/route.ts": API_ROUTE,
        "package-lock.json": `"express-rate-limit": "7.0.0"`,
      }),
    );
    expect(r.status).toBe("open");
  });
});

describe("std-sec-auth-guard", () => {
  it("a mutation route with no auth → MANUAL (critical) — heuristic, never a certain open", async () => {
    const r = await stdAuthGuard.run(makeCtx({ "app/api/orders/route.ts": API_ROUTE }));
    expect(r.status).toBe("manual");
    expect(r.level ?? "critical").toBe("critical");
  });
  it("a route with auth → pass", async () => {
    const r = await stdAuthGuard.run(
      makeCtx({
        "app/api/orders/route.ts": `import { auth } from "@clerk/nextjs"; export async function POST(req){ const { userId } = auth(); if(!userId) return new Response("401",{status:401}); await db.orders.create({}); }`,
      }),
    );
    expect(r.status).toBe("pass");
  });
  it("API route yoksa → na", async () => {
    const r = await stdAuthGuard.run(makeCtx({ "src/index.ts": "console.log(1)" }));
    expect(r.status).toBe("na");
  });
});

describe("std-sec-env-protection", () => {
  it("a committed real .env → open (critical)", async () => {
    const r = await stdEnvProtection.run(
      makeCtx(
        { ".env": "DATABASE_URL=postgres://user:pass@host/db", "package.json": "{}" },
        { tracked: [".env", "package.json"] },
      ),
    );
    expect(r.status).toBe("open");
    expect(r.level ?? "critical").toBe("critical");
  });
  it("a gitignored .env with the pattern present → pass", async () => {
    const r = await stdEnvProtection.run(
      makeCtx(
        { ".env": "DATABASE_URL=postgres://user:pass@host/db", ".gitignore": ".env*\n", "package.json": "{}" },
        { tracked: [".gitignore", "package.json"] },
      ),
    );
    expect(r.status).toBe("pass");
  });
  it(".gitignore has no .env pattern → open (warning)", async () => {
    const r = await stdEnvProtection.run(
      makeCtx({ ".gitignore": "node_modules\n", "package.json": "{}" }, { tracked: [".gitignore", "package.json"] }),
    );
    expect(r.status).toBe("open");
    expect(r.level).toBe("warning");
  });
});

describe("std-sec-hardcoded-secret", () => {
  it("a Stripe live key → open", async () => {
    const r = await stdHardcodedSecret.run(
      makeCtx({ "lib/pay.ts": `const key = "sk_test_${"a1B2c3D4e5F6g7H8"}";` }),
    );
    expect(r.status).toBe("open");
  });
  it("clean code → pass", async () => {
    const r = await stdHardcodedSecret.run(
      makeCtx({ "lib/pay.ts": `const key = process.env.STRIPE_KEY;` }),
    );
    expect(r.status).toBe("pass");
  });
});

describe("std-sec-headers", () => {
  it("a Next project with no config at all → open", async () => {
    const r = await stdSecurityHeaders.run(makeCtx({ "package.json": "{}" }));
    expect(r.status).toBe("open");
  });
  it("every header in next.config → pass", async () => {
    const r = await stdSecurityHeaders.run(
      makeCtx({
        "next.config.js": `headers: Content-Security-Policy X-Frame-Options X-Content-Type-Options Strict-Transport-Security Referrer-Policy`,
      }),
    );
    expect(r.status).toBe("pass");
  });
  it("partial headers → open (info) — the missing ones are listed", async () => {
    const r = await stdSecurityHeaders.run(
      makeCtx({ "next.config.js": `X-Frame-Options X-Content-Type-Options` }),
    );
    expect(r.status).toBe("open");
    expect(r.level).toBe("info");
    expect(r.detail).toContain("Content-Security-Policy");
  });
  it("Next 16: CSP in proxy.ts, the rest in next.config → pass (proxy.ts must be read)", async () => {
    // A real blind spot: middleware became proxy.ts in Next 16 and the nonce-based
    // CSP is generated there. Without scanning proxy.ts it would report a lone "missing CSP".
    const r = await stdSecurityHeaders.run(
      makeCtx({
        "next.config.ts": `X-Frame-Options X-Content-Type-Options Strict-Transport-Security Referrer-Policy`,
        "proxy.ts": `response.headers.set("Content-Security-Policy", csp)`,
      }),
    );
    expect(r.status).toBe("pass");
  });
});

describe("std-sec-rls", () => {
  it("Supabase with CREATE POLICY in a migration → pass", async () => {
    const r = await stdSupabaseRls.run(
      makeCtx({ "supabase/migrations/001.sql": "ALTER TABLE x ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON x;" }),
    );
    expect(r.status).toBe("pass");
  });
  it("Supabase ama repoda RLS izi yok → manuel (dashboard'da olabilir)", async () => {
    const r = await stdSupabaseRls.run(makeCtx({ "lib/db.ts": "supabase.from('x')" }));
    expect(r.status).toBe("manual");
  });
  it("not Supabase → na", async () => {
    const r = await stdSupabaseRls.run(makeCtx({}, { stack: { db: "postgres" } }));
    expect(r.status).toBe("na");
  });
});

describe("std-sec-input-validation", () => {
  it("zod in deps → pass", async () => {
    const r = await stdInputValidation.run(
      makeCtx({ "package.json": `{"dependencies":{"zod":"^3.0.0"}}`, "app/api/x/route.ts": API_ROUTE }),
    );
    expect(r.status).toBe("pass");
  });
  it("an API exists with no validation signal → manual", async () => {
    const r = await stdInputValidation.run(
      makeCtx({ "package.json": "{}", "app/api/x/route.ts": API_ROUTE }),
    );
    expect(r.status).toBe("manual");
  });
});

describe("std-perf-region", () => {
  it("regions declared → pass (with a manual note about DB alignment)", async () => {
    const r = await stdVercelRegion.run(makeCtx({ "vercel.json": `{"regions":["fra1"]}` }));
    expect(r.status).toBe("pass");
    expect(r.detail).toContain("manual");
  });
  it("vercel.json exists with no regions → open", async () => {
    const r = await stdVercelRegion.run(makeCtx({ "vercel.json": `{}` }));
    expect(r.status).toBe("open");
  });
  it("vercel.json yok → manuel (Vercel'de olmayabilir)", async () => {
    const r = await stdVercelRegion.run(makeCtx({ "package.json": "{}" }));
    expect(r.status).toBe("manual");
  });
});

describe("std-perf-sequential-await", () => {
  const manyAwaits = Array.from({ length: 6 }, (_, i) => `const x${i} = await q${i}();`).join("\n");
  it("6 await + Promise.all yok → manuel (sezgisel)", async () => {
    const r = await stdSequentialAwait.run(makeCtx({ "app/dashboard/page.tsx": manyAwaits }));
    expect(r.status).toBe("manual");
  });
  it("Promise.all is used → pass", async () => {
    const r = await stdSequentialAwait.run(
      makeCtx({ "app/dashboard/page.tsx": manyAwaits + "\nawait Promise.all([a,b]);" }),
    );
    expect(r.status).toBe("pass");
  });
});

describe("std-perf-loading", () => {
  it("app router with no loading.tsx at all → open", async () => {
    const r = await stdLoadingSkeleton.run(makeCtx({ "app/page.tsx": "export default function P(){}" }));
    expect(r.status).toBe("open");
  });
  it("loading.tsx exists → pass", async () => {
    const r = await stdLoadingSkeleton.run(
      makeCtx({ "app/page.tsx": "x", "app/loading.tsx": "export default function L(){}" }),
    );
    expect(r.status).toBe("pass");
  });
  it("not a Next app router → na", async () => {
    const r = await stdLoadingSkeleton.run(
      makeCtx({ "src/App.tsx": "x" }, { stack: { framework: "vite" } }),
    );
    expect(r.status).toBe("na");
  });
});

describe("std-perf-select-star", () => {
  it(".select('*') → open (info)", async () => {
    const r = await stdSelectStar.run(
      makeCtx({ "lib/db.ts": `const { data } = await supabase.from("orders").select("*");` }),
    );
    expect(r.status).toBe("open");
  });
  it("a narrowed select → pass", async () => {
    const r = await stdSelectStar.run(
      makeCtx({ "lib/db.ts": `const { data } = await supabase.from("orders").select("id, name");` }),
    );
    expect(r.status).toBe("pass");
  });
});

describe("runStandards (the whole profile)", () => {
  it("produces one result per check with correct score and category breakdown", async () => {
    const ctx = makeCtx({
      "app/api/orders/route.ts": API_ROUTE,
      ".gitignore": ".env*\n",
      "package.json": "{}",
    });
    const res = await runStandards(ctx);
    expect(res.profile).toBe("nocturn-standards");
    expect(res.checks.length).toBe(standardsChecks.length);
    expect(res.categories.security.score).toBeLessThanOrEqual(100);
    expect(res.categories.performance.score).toBeLessThanOrEqual(100);
    const sum =
      res.counts.pass + res.counts.open + res.counts.manual + res.counts.na;
    expect(sum).toBe(standardsChecks.length);
    // an open rate limit (warning −10) should lower the score
    const rl = res.checks.find((c) => c.id === "std-sec-rate-limit");
    expect(rl?.status).toBe("open");
    expect(res.categories.security.score).toBeLessThan(100);
    // manual results carry no penalty: only open ones lower the score
    const failPenalty = res.checks
      .filter((c) => c.status === "open")
      .reduce((n, c) => n + (c.level === "critical" ? 25 : c.level === "warning" ? 10 : 3), 0);
    expect(res.score).toBe(Math.max(0, 100 - failPenalty));
  });
});

describe("integrity standards — the audit list turned into rules", () => {
  it("all three categories reach the report", async () => {
    const r = await runStandards(makeCtx({ "package.json": "{}" }));
    expect(Object.keys(r.categories).sort()).toEqual(["integrity", "performance", "security"]);
    expect(r.categories.integrity.pass + r.categories.integrity.open
      + r.categories.integrity.manual + r.categories.integrity.na).toBeGreaterThan(10);
  });

  it("non-automatable items stay visible as MANUAL", async () => {
    // Part of the list cannot be answered by a static scan: a button in a provider
    // dashboard, whether a negative test was actually run. DROPPING those from the
    // list would be the fastest way to forget them.
    const r = await runStandards(makeCtx({ "package.json": "{}" }));
    const manuel = r.checks.filter((c) => c.category === "integrity" && c.status === "manual");
    expect(manuel.length).toBeGreaterThanOrEqual(5);
    // A bucket's public URL cannot be tested from outside; while it is on, every
    // document and backup is world-readable. It has to stay on the list.
    expect(manuel.some((c) => c.id === "integrity-bucket-public-url")).toBe(true);
  });

  it("manual items do not lower the score", async () => {
    // Otherwise every non-automatable item drags the score down permanently and
    // people stop looking at it.
    const r = await runStandards(makeCtx({ "package.json": "{}" }));
    expect(r.categories.integrity.score).toBeGreaterThan(0);
  });

  it("an automated item really fires: a hand-enumerated test list → open", async () => {
    const r = await runStandards(makeCtx({
      "package.json": JSON.stringify({
        scripts: { test: "node --test tests/a.test.mjs tests/b.test.mjs tests/c.test.mjs" },
      }),
      "tests/a.test.mjs": "", "tests/b.test.mjs": "", "tests/c.test.mjs": "",
    }));
    const kontrol = r.checks.find((c) => c.id === "integrity-test-list");
    expect(kontrol?.status).toBe("open");
  });

  it("the na status is preserved: with no SQL file the delete check is skipped", async () => {
    const r = await runStandards(makeCtx({ "package.json": "{}" }));
    const kontrol = r.checks.find((c) => c.id === "integrity-delete-guard");
    expect(kontrol?.status).toBe("na");
  });
});
