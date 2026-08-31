import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import type { Finding } from "../src/core/finding.js";
import type { StaticRule } from "../src/core/rule.js";

import { apiRouteAuthMissing } from "../src/static/api-route-auth-missing.js";
import { idorDirectObject } from "../src/static/idor-direct-object.js";
import { supabaseServiceRole } from "../src/static/supabase-service-role.js";
import { hardcodedSecrets } from "../src/static/hardcoded-secrets.js";
import { envCommitted } from "../src/static/env-committed.js";
import { nextPublicSecret } from "../src/static/next-public-secret.js";
import { weakHash } from "../src/static/weak-hash.js";
import { sqlInjection } from "../src/static/sql-injection.js";
import { dangerousEval } from "../src/static/dangerous-eval.js";
import { missingRateLimit } from "../src/static/missing-rate-limit.js";
import { securityHeadersConfig } from "../src/static/security-headers-config.js";
import { corsWildcard } from "../src/static/cors-wildcard.js";
import { jwtWeakVerification } from "../src/static/jwt-weak-verification.js";
import { webhookSignature } from "../src/static/webhook-signature.js";
import { auditLogging } from "../src/static/audit-logging.js";
import { ssrf } from "../src/static/ssrf.js";
import { sensitiveDataPlaintext } from "../src/static/sensitive-data-plaintext.js";
import { missingRls } from "../src/static/missing-rls.js";
import { kvkkSpecialCategory } from "../src/static/kvkk-special-category.js";
import { openRedirect } from "../src/static/open-redirect.js";
import { csrfMissing } from "../src/static/csrf-missing.js";
import { massAssignment } from "../src/static/mass-assignment.js";
import { externalScriptSri } from "../src/static/external-script-sri.js";
import { securityTxt } from "../src/static/security-txt.js";
import { scanGitDiff } from "../src/static/secrets-git-history.js";
import { spoofableClientIp } from "../src/static/spoofable-client-ip.js";
import { sqlIdentifierInjection } from "../src/static/sql-identifier-injection.js";
import { sqliteNoBusyTimeout } from "../src/static/sqlite-no-busy-timeout.js";

async function run(
  rule: StaticRule,
  files: Record<string, string>,
  overrides?: Parameters<typeof makeCtx>[1],
): Promise<Finding[]> {
  return Promise.resolve(rule.run(makeCtx(files, overrides)));
}

describe("A01 — api-route-auth-missing", () => {
  it("a DB-WRITING (mutation) route with no auth → high, likely", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/orders/route.ts": `export async function POST(req){ const b = await req.json(); await db.orders.create({ data: b }); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].confidence).toBe("likely");
  });
  // A project's only high finding was `examples/d1/app/api/notes/route.ts` —
  // Next routes only the ROOT app/ directory, so that file is never served.
  it("CLEAN: a non-root app/ (examples/…) route does not count", async () => {
    const f = await run(apiRouteAuthMissing, {
      "examples/d1/app/api/notes/route.ts": `export async function POST(req){ const b = await req.json(); await db.insert(notes).values(b); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("BAD: the same file under the root app/ does produce a finding", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/notes/route.ts": `export async function POST(req){ const b = await req.json(); await db.insert(notes).values(b); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
  });
  it("a DB-READING (GET) route with no session signal at all → info (inventory)", async () => {
    // Calling this a "finding" sends the team chasing nothing: an open read with
    // no identity is usually a DESIGN CHOICE. It is listed as inventory:
    // "this is read without identity — on purpose?"
    const f = await run(apiRouteAuthMissing, {
      "app/api/orders/route.ts": `export async function GET(req){ const data = await db.orders.findMany(); return Response.json(data); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
  });

  it("CLEAN: a cached response (revalidate) cannot be user-specific", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/district-scores/route.ts": `export const revalidate = 3600;
export async function GET(){ const rows = await prisma.districtData.findMany(); return NextResponse.json(rows); }`,
    });
    expect(f.length).toBe(0);
  });

  it("a session signal EXISTS but was not recognised → low (a real suspicion)", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/orders/route.ts": `export async function GET(req){ const s = req.headers.get("Authorization"); const data = await db.orders.findMany(); return Response.json(data); }`,
    });
    expect(f.length).toBe(0);
  });
  it("a login (auth boundary) route → NO finding (it produces auth, does not consume it)", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/admin/login/route.ts": `export async function POST(req){ const b = await req.json(); const ok = await db.users.findFirst(); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("a public form with rate limiting and validation (newsletter) → NO finding", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/newsletter/route.ts": `import { rateLimit } from "@/lib/rate-limit";
const EMAIL_RE = /^[^@]+@[^@]+$/;
export async function POST(req){ const rl = rateLimit("nl"); if(!rl.ok) return new Response("429",{status:429}); const b = await req.json(); if(!EMAIL_RE.test(b.email)) return new Response("bad",{status:400}); await db.subscriber.upsert({ where:{email:b.email}, create:{email:b.email, confirmed:false} }); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("public GET listing plus an isAuthorized mutation → NO finding", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/blog/route.ts": `export async function GET(req){ return Response.json(await db.posts.findMany()); }
export async function POST(req){ if(!isAuthorized(req)) return new Response("401",{status:401}); await db.posts.create({data:await req.json()}); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("a public route that never touches the DB (og image) → no finding", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/og/route.tsx": `import { ImageResponse } from "next/og"; export async function GET(req){ return new ImageResponse(<div>hi</div>); }`,
    });
    expect(f.length).toBe(0);
  });
  it("a webhook with signature verification → no finding", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/webhook/route.ts": `export async function POST(req){ const sig = req.headers.get("stripe-signature"); const event = stripe.webhooks.constructEvent(body, sig, secret); await db.order.update({}); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("produces no finding on a route that has auth", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/orders/route.ts": `import { auth } from "@clerk/nextjs";
export async function GET(req){ const { userId } = auth(); if(!userId) return new Response("no",{status:401}); return await db.orders.findMany(); }`,
    });
    expect(f.length).toBe(0);
  });
  it("API olmayan dosyada tetiklenmez", async () => {
    const f = await run(apiRouteAuthMissing, {
      "lib/util.ts": `export function GET(){ return 1; }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A01 — idor-direct-object", () => {
  it("produces a finding on a params.id query with no ownership check", async () => {
    const f = await run(idorDirectObject, {
      "app/api/doc/route.ts": `export async function GET(req,{params}){ const doc = await supabase.from("docs").select().eq("id", params.id).single(); return Response.json(doc); }`,
    });
    expect(f.length).toBe(1);
  });
  it("produces no finding when there is a user_id filter", async () => {
    const f = await run(idorDirectObject, {
      "app/api/doc/route.ts": `export async function GET(req,{params}){ const doc = await supabase.from("docs").select().eq("id", params.id).eq("user_id", session.user.id).single(); return doc; }`,
    });
    expect(f.length).toBe(0);
  });
  // In one project a permission-list gate (permissions.includes) was not recognised.
  it("CLEAN: getUser plus a permissions.includes gate → NO finding", async () => {
    const f = await run(idorDirectObject, {
      "app/api/basit/musteri-urunler/route.ts": `export async function GET(request){ const user = await getUser(); if(!user) return Response.json({},{status:401}); const { permissions } = await getUserRoleData(); if(!permissions.includes("orders")) return Response.json({},{status:403}); const customerId = new URL(request.url).searchParams.get("customer_id"); const { data } = await supabase.from("order_items").select().eq("orders.customer_id", customerId); return Response.json(data); }`,
    });
    expect(f.length).toBe(0);
  });
  it("BAD: with no gate at all the same shape still produces a finding", async () => {
    const f = await run(idorDirectObject, {
      "app/api/basit/musteri-urunler/route.ts": `export async function GET(request){ const customerId = new URL(request.url).searchParams.get("customer_id"); const { data } = await supabase.from("order_items").select().eq("orders.customer_id", customerId); return Response.json(data); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
  it("a route guarded by requireAdmin/requireGate → NO finding (single-tenant)", async () => {
    const f = await run(idorDirectObject, {
      "app/api/export/route.ts": `export async function GET(req){ const unauth = requireAdmin(req); if(unauth) return unauth; const id = req.nextUrl.searchParams.get("conversation_id"); const c = await supabase.from("conv").select().eq("id", id).single(); return Response.json(c); }`,
    });
    expect(f.length).toBe(0);
  });
  it("a behavioural query param ('format') → not an object ID, NO finding", async () => {
    const f = await run(idorDirectObject, {
      "app/api/export/route.ts": `export async function GET(req){ const format = req.nextUrl.searchParams.get("format"); const rows = await supabase.from("t").select().eq("kind", format).single(); return Response.json(rows); }`,
    });
    expect(f.length).toBe(0);
  });
  it("a public reference/lookup param (city/district) → not IDOR, NO finding", async () => {
    const f = await run(idorDirectObject, {
      "app/api/rapor/route.ts": `export async function GET(req){ const city = req.nextUrl.searchParams.get("city"); const district = req.nextUrl.searchParams.get("district"); const d = districtData.find(x => x.city === city); return Response.json(d); }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A01 — supabase-service-role", () => {
  it("reports service_role usage, and critical in a client file", async () => {
    const f = await run(supabaseServiceRole, {
      "components/Admin.tsx": `"use client"; const c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("critical");
  });
  it("produces no finding with a clean anon key", async () => {
    const f = await run(supabaseServiceRole, {
      "lib/db.ts": `const c = createClient(url, process.env.SUPABASE_ANON_KEY);`,
    });
    expect(f.length).toBe(0);
  });

  // One run produced 36 "medium" findings across 4 projects; 17 in one project's
  // maintenance scripts, 3 in another's .sql files. All of them by design. Using
  // service_role where the client cannot reach is inventory, not risk.
  it("CLEAN score: service_role in a maintenance script → info (inventory, not a finding)", async () => {
    const f = await run(supabaseServiceRole, {
      "scripts/backup-data.mjs": `const c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].title).toMatch(/server-locked/);
  });
  it("CLEAN-skor: SQL migration'da service_role GRANT'i → info", async () => {
    const f = await run(supabaseServiceRole, {
      "supabase/patches/roles.sql": `grant select on public.ogrenciler to service_role;`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
  });
  it("BAD: still medium in an ambiguous server file", async () => {
    const f = await run(supabaseServiceRole, {
      "lib/supabase/admin.ts": `const c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("BAD: a client file stays critical even under scripts/", async () => {
    const f = await run(supabaseServiceRole, {
      "scripts/Panel.tsx": `"use client"; const c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    });
    expect(f[0].severity).toBe("critical");
  });
});

describe("A02 — hardcoded-secrets", () => {
  it("Stripe live key'i critical + kesin yakalar", async () => {
    const f = await run(hardcodedSecrets, {
      "lib/pay.ts": `const key = "sk_test_abcdEFGH1234ijkl";`,
    });
    expect(f.some((x) => x.severity === "critical")).toBe(true);
    // the engine stamps the confidence; the rule default is certain
    expect(hardcodedSecrets.confidence).toBe("certain");
  });
  it("produces no finding for process.env usage", async () => {
    const f = await run(hardcodedSecrets, {
      "lib/pay.ts": `const key = process.env.STRIPE_SECRET_KEY; const apiKey = "your-api-key-here";`,
    });
    expect(f.length).toBe(0);
  });
  it("a secret in a gitignored .env.local → NOT REPORTED as code-embedded", async () => {
    const f = await run(
      hardcodedSecrets,
      { ".env.local": `STRIPE_SECRET_KEY=sk_test_abcdEFGH1234ijkl` },
      { tracked: [] }, // untracked (gitignored)
    );
    expect(f.length).toBe(0);
  });
  it("a secret in a git-tracked (committed) .env → caught as code-embedded", async () => {
    const f = await run(
      hardcodedSecrets,
      { ".env": `STRIPE_SECRET_KEY=sk_test_abcdEFGH1234ijkl` },
      { tracked: [".env"] },
    );
    expect(f.some((x) => x.severity === "critical")).toBe(true);
  });
  it("an env-var NAME is assigned (const SECRET = 'AGGREGATOR_WEBHOOK_SECRET') → NO finding", async () => {
    const f = await run(hardcodedSecrets, {
      "src/lib/adapters/aggregator.ts": `const SECRET = "AGGREGATOR_WEBHOOK_SECRET";\nconst KEY = "AGGREGATOR_API_KEY";\nconst v = env(SECRET);`,
    });
    expect(f.length).toBe(0);
  });
  it("a key in a scraped third-party HTML dump → NO finding", async () => {
    const f = await run(hardcodedSecrets, {
      "lgbs_raw.html": `<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyD1234567890abcdefghijklmnopqrstuvw"></script>`,
    });
    expect(f.length).toBe(0);
  });
  it("a real embedded service_role JWT (dump-schema.mjs) → high certain (PRESERVED)", async () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEF";
    const f = await run(hardcodedSecrets, {
      "scripts/dump-schema.mjs": `const key = "${jwt}";`,
    });
    expect(f.some((x) => x.severity === "high" || x.severity === "critical")).toBe(true);
  });
});

describe("A02 — env-committed", () => {
  it("a git-tracked (committed) .env → high certain", async () => {
    const f = await run(
      envCommitted,
      {
        ".env": `DATABASE_URL=postgres://user:realpassword@host:5432/db\nSTRIPE_KEY=sk_test_xxxxxxxxxxxx`,
        "package.json": `{"name":"x"}`,
        ".gitignore": `node_modules/`,
      },
      { tracked: [".env", "package.json", ".gitignore"] },
    );
    const high = f.find((x) => x.severity === "high");
    expect(high).toBeTruthy();
    expect(high!.title).toContain("has been committed to git");
    expect(high!.confidence).toBe("certain");
  });
  it("a gitignored (untracked) .env.local → does NOT produce high (info)", async () => {
    const f = await run(
      envCommitted,
      {
        ".env.local": `DATABASE_URL=postgres://user:realpassword@host:5432/db`,
        "package.json": `{"name":"x"}`,
        ".gitignore": `node_modules/\n.env*`,
      },
      { tracked: ["package.json", ".gitignore"] },
    );
    expect(f.filter((x) => x.severity === "high").length).toBe(0);
    expect(f.some((x) => x.severity === "info")).toBe(true);
  });
  it("produces no high when .gitignore covers .env and the file is absent", async () => {
    const f = await run(envCommitted, {
      "package.json": `{"name":"x"}`,
      ".gitignore": `node_modules/\n.env*`,
    });
    expect(f.filter((x) => x.severity === "high").length).toBe(0);
  });
});

describe("A02 — next-public-secret", () => {
  it("SERVICE_ROLE under NEXT_PUBLIC_ is critical", async () => {
    const f = await run(nextPublicSecret, {
      "lib/env.ts": `const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("critical");
  });
  it("NEXT_PUBLIC_ANON_KEY temiz", async () => {
    const f = await run(nextPublicSecret, {
      "lib/env.ts": `const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY; const p = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A02 — weak-hash", () => {
  it("md5 for a password → finding", async () => {
    const f = await run(weakHash, {
      "lib/auth.ts": `const hashed = createHash("md5").update(password).digest("hex");`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
  it("bcrypt temiz", async () => {
    const f = await run(weakHash, {
      "lib/auth.ts": `const hashed = await bcrypt.hash(password, 12);`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A03 — sql-injection", () => {
  it("template literal + input → bulgu", async () => {
    const f = await run(sqlInjection, {
      "app/api/u/route.ts": `export async function GET(req){ const id = req.query.id; const r = await db.query(\`SELECT * FROM users WHERE id = \${id}\`); return r; }`,
    });
    expect(f.length).toBe(1);
  });
  it("parametreli sorgu temiz", async () => {
    const f = await run(sqlInjection, {
      "app/api/u/route.ts": `const r = await db.query("SELECT * FROM users WHERE id = $1", [id]);`,
    });
    expect(f.length).toBe(0);
  });
  it("a JSX closing tag </div></div> → not SQL, NO finding", async () => {
    const f = await run(sqlInjection, {
      "src/CigkoftePanel.jsx": `return (<div>{items.map(i => <div key={i.id}>{i.name}</div>)}</div></div>);`,
    });
    expect(f.length).toBe(0);
  });
  it("a Tailwind className template literal (from-*) → not SQL, NO finding", async () => {
    const f = await run(sqlInjection, {
      "src/app/exchanges/page.tsx": `const cls = \`bg-gradient-to-r from-\${color}-500 to-blue-500 px-4\`; return <div className={cls} />;`,
    });
    expect(f.length).toBe(0);
  });
  it("a fetch body JSON.stringify (PostgREST HTTP) → not SQL, NO finding", async () => {
    const f = await run(sqlInjection, {
      "scripts/seed.ts": `await fetch(url, { method: "POST", body: JSON.stringify(rec), headers });`,
    });
    expect(f.length).toBe(0);
  });
  it("Supabase ORM builder (.from().select().or().ilike()) → parametreli, bulgu YOK", async () => {
    const f = await run(sqlInjection, {
      "lib/search.ts": `const { data } = await supabase.from("products").select("*").or(\`name.ilike.%\${q}%\`).eq("active", true);`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A03 — dangerous-eval", () => {
  it("dangerouslySetInnerHTML → bulgu", async () => {
    const f = await run(dangerousEval, {
      "components/Post.tsx": `export default function P({html}){ return <div dangerouslySetInnerHTML={{__html: html}} />; }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
  it("eval yoksa temiz", async () => {
    const f = await run(dangerousEval, {
      "components/Post.tsx": `export default function P({text}){ return <div>{text}</div>; }`,
    });
    expect(f.length).toBe(0);
  });
  it("dangerouslySetInnerHTML → kesin", async () => {
    const f = await run(dangerousEval, {
      "components/Post.tsx": `export default function P({html}){ return <div dangerouslySetInnerHTML={{__html: html}} />; }`,
    });
    expect(f[0].confidence).toBe("certain");
    expect(f[0].severity).toBe("high");
  });
  it("child_process as fixed tooling → low, likely (NOT high)", async () => {
    const f = await run(dangerousEval, {
      "scripts/build.ts": `import { execSync } from "child_process"; execSync("tsc -p tsconfig.json");`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
    const cp = f.find((x) => x.title.includes("child_process"));
    expect(cp!.severity).toBe("low");
    expect(cp!.confidence).toBe("likely");
  });
  it("child_process built from user input → high", async () => {
    const f = await run(dangerousEval, {
      "app/api/run/route.ts": `import { exec } from "child_process"; export async function POST(req){ const { cmd } = await req.json(); exec(\`convert \${cmd}\`); }`,
    });
    const cp = f.find((x) => x.title.includes("child_process"));
    expect(cp!.severity).toBe("high");
  });
  it("JSON-LD structured data (application/ld+json) → bulgu YOK", async () => {
    const f = await run(dangerousEval, {
      "app/layout.tsx": `const jsonLd = { "@type": "Org", name: "X" };
export default function L(){ return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />; }`,
    });
    const dom = f.find((x) => x.title.includes("dangerouslySetInnerHTML"));
    expect(dom).toBeFalsy();
  });
  it("statik hardcoded string (setTimeout failsafe) → dom bulgusu YOK", async () => {
    const f = await run(dangerousEval, {
      "app/layout.tsx": `export default function L(){ return <script dangerouslySetInnerHTML={{ __html: "setTimeout(function(){document.body.classList.add('in')},2500);" }} />; }`,
    });
    const dom = f.find((x) => x.title.includes("dangerouslySetInnerHTML"));
    expect(dom).toBeFalsy();
  });
  it("service worker template literal (interpolasyonsuz) → dom bulgusu YOK", async () => {
    const f = await run(dangerousEval, {
      "app/layout.tsx": "export default function L(){ return <script dangerouslySetInnerHTML={{ __html: `if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}` }} />; }",
    });
    const dom = f.find((x) => x.title.includes("dangerouslySetInnerHTML"));
    expect(dom).toBeFalsy();
  });
  it("DOMPurify/sanitize applied (without ld+json) → NO dom finding", async () => {
    const f = await run(dangerousEval, {
      "components/RichText.tsx": `export function RT({ body }){ const clean = DOMPurify.sanitize(body); return <div dangerouslySetInnerHTML={{ __html: clean }} />; }`,
    });
    const dom = f.find((x) => x.title.includes("dangerouslySetInnerHTML"));
    expect(dom).toBeFalsy();
  });
  it("__html from a prop or request (tainted) → dom high/certain", async () => {
    const f = await run(dangerousEval, {
      "components/Comment.tsx": `export default function C({ userComment }){ return <div dangerouslySetInnerHTML={{ __html: userComment }} />; }`,
    });
    const dom = f.find((x) => x.title.includes("dangerouslySetInnerHTML"));
    expect(dom).toBeTruthy();
    expect(dom!.severity).toBe("high");
    expect(dom!.confidence).toBe("certain");
  });
});

describe("A04 — missing-rate-limit", () => {
  it("login route'unda rate-limit yok → bulgu", async () => {
    const f = await run(missingRateLimit, {
      "app/api/login/route.ts": `export async function POST(req){ const {email,password}=await req.json(); return signIn(email,password); }`,
    });
    expect(f.length).toBe(1);
  });
  it("ratelimit varsa temiz", async () => {
    const f = await run(missingRateLimit, {
      "app/api/login/route.ts": `import { Ratelimit } from "@upstash/ratelimit"; export async function POST(req){ await ratelimit.limit(ip); return signIn(); }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A05 — security-headers-config", () => {
  it("CSP eksik next.config → bulgu", async () => {
    const f = await run(securityHeadersConfig, {
      "next.config.js": `module.exports = { reactStrictMode: true };`,
    });
    expect(f.some((x) => x.title.includes("Content-Security-Policy"))).toBe(true);
  });
  it("clean when every header is declared", async () => {
    const f = await run(securityHeadersConfig, {
      "next.config.js": `module.exports = { async headers(){ return [{source:"/(.*)",headers:[
        {key:"Content-Security-Policy",value:"default-src 'self'"},
        {key:"X-Frame-Options",value:"DENY"},
        {key:"X-Content-Type-Options",value:"nosniff"},
        {key:"Strict-Transport-Security",value:"max-age=63072000"},
        {key:"Referrer-Policy",value:"strict-origin-when-cross-origin"}]}]; } };`,
    });
    expect(f.length).toBe(0);
  });
  it("does not run in a vite project", async () => {
    const f = await run(
      securityHeadersConfig,
      { "vite.config.ts": `export default {}` },
      { stack: { framework: "vite" } },
    );
    expect(f.length).toBe(0);
  });
});

describe("A05 — cors-wildcard", () => {
  it("wildcard + credentials → high", async () => {
    const f = await run(corsWildcard, {
      "app/api/x/route.ts": `const h = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true" };`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
  it("allowlist origin temiz", async () => {
    const f = await run(corsWildcard, {
      "app/api/x/route.ts": `const h = { "Access-Control-Allow-Origin": "https://app.example.com" };`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A07 — jwt-weak-verification", () => {
  it("alg none → critical", async () => {
    const f = await run(jwtWeakVerification, {
      "lib/jwt.ts": `const token = jwt.sign(payload, key, { algorithm: "none" });`,
    });
    expect(f.some((x) => x.severity === "critical")).toBe(true);
  });
  it("decode-only ile yetki → bulgu", async () => {
    const f = await run(jwtWeakVerification, {
      "lib/jwt.ts": `const decoded = jwt.decode(token); if(decoded.role === "admin"){ allow(); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
  it("jwt.verify temiz", async () => {
    const f = await run(jwtWeakVerification, {
      "lib/jwt.ts": `const decoded = jwt.verify(token, secret, { algorithms: ["HS256"] }); if(decoded.role==="admin"){}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A08 — webhook-signature", () => {
  it("stripe webhook imza yok → bulgu", async () => {
    const f = await run(webhookSignature, {
      "app/api/stripe/webhook/route.ts": `export async function POST(req){ const body = await req.json(); if(body.type==="checkout.completed"){ fulfill(body); } return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
  });
  it("constructEvent ile temiz", async () => {
    const f = await run(webhookSignature, {
      "app/api/stripe/webhook/route.ts": `export async function POST(req){ const sig = req.headers.get("stripe-signature"); const event = stripe.webhooks.constructEvent(body, sig, secret); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A09 — audit-logging", () => {
  it("login route'unda log yok → info bulgu", async () => {
    const f = await run(auditLogging, {
      "app/api/login/route.ts": `export async function POST(req){ return signIn(); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
  });
  it("logger varsa temiz", async () => {
    const f = await run(auditLogging, {
      "app/api/login/route.ts": `export async function POST(req){ logger.info("login attempt"); return signIn(); }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A10 — ssrf", () => {
  it("a fetch to a user-supplied url → finding", async () => {
    const f = await run(ssrf, {
      "app/api/proxy/route.ts": `export async function GET(req){ const target = req.query.url; const r = await fetch(target); return r; }`,
    });
    expect(f.length).toBe(1);
  });
  it("allowlist varsa temiz", async () => {
    const f = await run(ssrf, {
      "app/api/proxy/route.ts": `const ALLOWED_HOSTS = ["api.example.com"]; export async function GET(req){ const target = req.query.url; const u = new URL(target); if(!ALLOWED_HOSTS.includes(u.hostname)) throw new Error("no"); const r = await fetch(target); return r; }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A02 — sensitive-data-plaintext", () => {
  it("a national id String in Prisma → low/likely compliance note (DDL, NOT high)", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "prisma/schema.prisma": `model User {\n  id       Int    @id\n  tc_kimlik String\n  email    String\n}`,
    });
    // A pure DDL column definition → not high, a low/likely compliance note.
    expect(f.some((x) => x.severity === "low")).toBe(true);
    expect(f.some((x) => x.severity === "high")).toBe(false);
    expect(f[0].cwe).toBe("CWE-311");
    expect(f[0].confidence).toBe("likely");
  });
  it("a NextAuth adapter refresh_token/access_token schema field → allowlisted (NO finding)", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "prisma/schema.prisma": `model Account {\n  id            Int    @id\n  refresh_token String? @db.Text\n  access_token  String? @db.Text\n  id_token      String? @db.Text\n}`,
    });
    expect(f.length).toBe(0);
  });
  it("a token written to the DB in plaintext (unencrypted persist) → high/certain", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "lib/tokens.ts": `await db.tokens.insert({ access_token: googleToken, provider: "google" });`,
    });
    const t = f.find((x) => x.title.includes("Token or secret"));
    expect(t).toBeTruthy();
    expect(t!.severity).toBe("high");
    expect(t!.confidence).toBe("certain");
  });
  it("SQL'de ssn varchar → bulgu", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "migrations/001.sql": `CREATE TABLE patients (\n  id serial primary key,\n  ssn varchar(11) not null,\n  cvv text\n);`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
  it("an access_token written to the DB in plaintext in code → finding", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "lib/oauth.ts": `await prisma.account.create({ data: { access_token: token, userId } });`,
    });
    expect(f.some((x) => x.title.includes("Token or secret"))).toBe(true);
  });
  it("written through an encryptToken(...) wrapper → does NOT produce a Token/secret finding", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "server.ts": `await prisma.account.create({ data: { access_token: encryptToken(pageToken), userId } }); // K2: at-rest AES-256-GCM`,
    });
    expect(f.some((x) => x.title.includes("Token or secret"))).toBe(false);
  });
  it("encrypted with bytea/pgp_sym_encrypt → clean", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "migrations/001.sql": `CREATE TABLE patients ( id serial, tc_kimlik bytea, ssn bytea default pgp_sym_encrypt('', '') );`,
    });
    expect(f.length).toBe(0);
  });
  it("hassas olmayan alanlar → temiz", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "prisma/schema.prisma": `model Post { id Int @id\n  title String\n  body  String\n}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A01 — missing-rls", () => {
  // The rule only runs in real Supabase client projects (anon key + client access).
  const SUPA = {
    "package.json": `{"dependencies":{"@supabase/supabase-js":"^2.0.0"}}`,
    "src/lib/supabase.ts": `import { createClient } from "@supabase/supabase-js";
export const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);`,
  };
  it("a public table without RLS in a Supabase client project → high", async () => {
    const f = await run(missingRls, {
      ...SUPA,
      "supabase/migrations/001.sql": `create table public.profiles ( id uuid primary key, bio text );`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
  it("RLS on but no policy → fail-closed, NO finding (the old medium was an FP)", async () => {
    const f = await run(missingRls, {
      ...SUPA,
      "supabase/migrations/001.sql": `create table public.notes ( id uuid primary key );\nalter table public.notes enable row level security;`,
    });
    expect(f.length).toBe(0);
  });
  it("'alter table if exists ... enable RLS' in the same file → NO finding", async () => {
    const f = await run(missingRls, {
      ...SUPA,
      "supabase/migrations/001.sql": `create table if not exists public.snap ( id uuid primary key );\ncreate table if not exists public.evt ( id uuid primary key );\nalter table if exists public.snap enable row level security;\nalter table if exists public.evt  enable row level security;`,
    });
    expect(f.length).toBe(0);
  });
  it("RLS + policy → temiz", async () => {
    const f = await run(missingRls, {
      ...SUPA,
      "supabase/migrations/001.sql": `create table public.notes ( id uuid primary key, user_id uuid );\nalter table public.notes enable row level security;\ncreate policy "owner" on public.notes for select using (auth.uid() = user_id);`,
    });
    expect(f.length).toBe(0);
  });
  it("a Prisma migration (server-side owner conn, not Supabase) → NO finding", async () => {
    const f = await run(missingRls, {
      "package.json": `{"dependencies":{"@prisma/client":"^6.0.0","next-auth":"^4.0.0"}}`,
      "prisma/migrations/0001_init/migration.sql": `CREATE TABLE "User" ( id TEXT PRIMARY KEY, email TEXT );`,
    });
    expect(f.length).toBe(0);
  });
  it("Drizzle migration (Neon + server-only) → bulgu YOK", async () => {
    const f = await run(missingRls, {
      "package.json": `{"dependencies":{"drizzle-orm":"^0.3.0","@neondatabase/serverless":"^0.9.0"}}`,
      "drizzle/0000_init.sql": `CREATE TABLE "subscribers" ( id serial primary key, email text );`,
    });
    expect(f.length).toBe(0);
  });
  it("a non-Supabase project (no anon key) → does not run at all", async () => {
    const f = await run(missingRls, {
      "package.json": `{"dependencies":{"pg":"^8.0.0"}}`,
      "db/schema.sql": `create table public.profiles ( id uuid primary key, bio text );`,
    });
    expect(f.length).toBe(0);
  });
  it("an auth-schema table → ignored", async () => {
    const f = await run(missingRls, {
      ...SUPA,
      "supabase/migrations/001.sql": `create table auth.sessions ( id uuid primary key );`,
    });
    expect(f.length).toBe(0);
  });
});

describe("KVKK — special-category-data", () => {
  it("health kolonu → info bulgu", async () => {
    const f = await run(kvkkSpecialCategory, {
      "prisma/schema.prisma": `model Patient { id Int @id\n  health_notes String\n}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
  });
  it("ordinary fields → clean", async () => {
    const f = await run(kvkkSpecialCategory, {
      "prisma/schema.prisma": `model User { id Int @id\n  name String\n}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A01 — open-redirect", () => {
  it("a redirect to an unvalidated searchParams target → finding", async () => {
    const f = await run(openRedirect, {
      "app/api/go/route.ts": `export function GET(req){ const next = new URL(req.url).searchParams.get("next"); return redirect(next); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe("CWE-601");
  });
  it("a startsWith('/') validation → clean", async () => {
    const f = await run(openRedirect, {
      "app/api/go/route.ts": `export function GET(req){ const next = req.query.next; if(!next.startsWith("/")) return redirect("/"); return redirect(next); }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A01 — csrf-missing", () => {
  it("cookie oturumlu POST'ta CSRF yok → bulgu", async () => {
    const f = await run(csrfMissing, {
      "app/api/profile/route.ts": `import { cookies } from "next/headers"; export async function POST(req){ const c = cookies(); await db.user.update({ data: {} }); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("CSRF token validation → clean", async () => {
    const f = await run(csrfMissing, {
      "app/api/profile/route.ts": `import { cookies } from "next/headers"; export async function POST(req){ const c = cookies(); if(req.headers.get("x-csrf-token")!==csrfToken) return new Response("no",{status:403}); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("a Bearer token API → closed to CSRF, clean", async () => {
    const f = await run(csrfMissing, {
      "app/api/profile/route.ts": `export async function POST(req){ const auth = req.headers.get("authorization"); const session = getServerSession(); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });

  // One project produced 10 findings, all of them next-auth v4 (SameSite=Lax by
  // default) plus a `request.json()` body. There is no explicit token — true; but
  // "an attacker can trigger requests with the victim's session" is not: a
  // cross-site form cannot send JSON, and a Lax cookie is not sent on a cross-site POST.
  it("a JSON body plus next-auth (Lax default) → low rather than medium", async () => {
    const f = await run(csrfMissing, {
      "app/api/forum/threads/route.ts": `import { getServerSession } from "next-auth"; export async function POST(request){ const session = await getServerSession(authOptions); const body = await request.json(); await prisma.thread.create({ data: {} }); return NextResponse.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("low");
    expect(f[0].description).toMatch(/NOT exploitable/);
  });
  it("CLEAN: a route file with only GET has no CSRF surface", async () => {
    const f = await run(csrfMissing, {
      "app/api/liste/route.ts": `import { cookies } from "next/headers";
export async function GET(req){ const c = cookies(); return Response.json(await db.select()); }`,
    });
    expect(f.length).toBe(0);
  });

  it("`Response.json(...)` writes a response, it does not expect a JSON body", async () => {
    // Text search confused the two, so every handler writing a response could
    // count as "protected".
    const f = await run(csrfMissing, {
      "app/api/kayit/route.ts": `import { cookies } from "next/headers";
export async function POST(req){ const c = cookies(); const form = await req.formData(); await db.insert(t).values({}); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });

  it("a project writing its own session: SameSite is NOT ASSUMED, it is READ from the cookie", async () => {
    const f = await run(csrfMissing, {
      "app/chatgpt-auth.ts": `export const SESSION_COOKIE = "s";
export function setSessionCookie(v: string) {
  return { name: SESSION_COOKIE, value: v, httpOnly: true, sameSite: "lax", secure: true };
}`,
      "app/api/auth/route.ts": `import { cookies } from "next/headers";
export async function POST(request){ const c = cookies(); const body = await request.json(); await db.insert(t).values({}); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("low");
  });

  it("CLEAN: a DELETE that reads no body does not unfairly push the file to medium", async () => {
    // A cross-site HTML form can only send GET/POST; DELETE needs fetch, which
    // hits the preflight. Two files in one project were wrongly marked medium
    // because of this.
    const f = await run(csrfMissing, {
      "app/api/alert/route.ts": `import { getServerSession } from "next-auth";
export async function POST(req){ const s = await getServerSession(authOptions); const b = await req.json(); await db.insert(t).values({}); return NextResponse.json({ok:true}); }
export async function DELETE(req){ const s = await getServerSession(authOptions); await db.delete(t); return NextResponse.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("low");
  });

  it("BAD: a cookie-session handler accepting a form body → stays medium", async () => {
    const f = await run(csrfMissing, {
      "app/api/profile/route.ts": `import { cookies } from "next/headers"; export async function POST(req){ const c = cookies(); const form = await req.formData(); await db.user.update({ data: {} }); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
});

describe("A01 — mass-assignment", () => {
  it("req.body straight into update → finding", async () => {
    const f = await run(massAssignment, {
      "app/api/u/route.ts": `export async function PUT(req){ const body = await req.json(); return prisma.user.update({ where:{id}, data: body }); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe("CWE-915");
  });
  it("...req.body spread → bulgu", async () => {
    const f = await run(massAssignment, {
      "app/api/u/route.ts": `export async function POST(req){ return prisma.user.create({ data: { ...req.body } }); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
  it("schema-validated fields → clean", async () => {
    const f = await run(massAssignment, {
      "app/api/u/route.ts": `export async function PUT(req){ const input = schema.parse(await req.json()); return prisma.user.update({ where:{id}, data: { name: input.name } }); }`,
    });
    expect(f.length).toBe(0);
  });

  // In one run the line called "mass assignment" in two projects was actually
  // `res.json({ ...report, generatedAt: new Date()... })`. The sink was triggered
  // by `new Date(`, the supposed "input" was a report the server generated
  // itself, and the target was the client, not the DB. Three mistakes, one line.
  it("CLEAN: spreading into a res.json response is not a DB write", async () => {
    const f = await run(massAssignment, {
      "server.ts": `app.get('/r/:id', async (req,res)=>{ const report = await buildReport(req.params.id); res.json({ ...report, generatedAt: new Date().toISOString() }); });`,
    });
    expect(f.length).toBe(0);
  });
  it("CLEAN: `new Date(` alone is not a DB sink", async () => {
    const f = await run(massAssignment, {
      "server.ts": `const kayit = { ...gelen, at: new Date() };`,
    });
    expect(f.length).toBe(0);
  });
  it("CLEAN: passing input as an ARGUMENT does not taint the variable", async () => {
    const f = await run(massAssignment, {
      "server.ts": `app.post('/x', async (req,res)=>{ const rapor = await uret(req.params.id); await db.insert(tablo).values({ ...rapor }); });`,
    });
    expect(f.length).toBe(0);
  });
  it("BAD: assigning the input ITSELF and spreading it into the DB is still a finding", async () => {
    const f = await run(massAssignment, {
      "server.ts": `app.post('/x', async (req,res)=>{ const gelen = req.body; await db.insert(tablo).values({ ...gelen }); });`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
  it("BAD: a real DB update rather than NextResponse.json → finding", async () => {
    const f = await run(massAssignment, {
      "app/api/u/route.ts": `export async function PUT(req){ const body = await req.json(); await prisma.user.update({ where:{id}, data: { ...body } }); return NextResponse.json({ ok:true }); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});

describe("A08 — external-script-sri", () => {
  it("integrity'siz harici script → bulgu", async () => {
    const f = await run(externalScriptSri, {
      "public/index.html": `<html><head><script src="https://cdn.example.com/a.js"></script></head></html>`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("integrity + crossorigin → temiz", async () => {
    const f = await run(externalScriptSri, {
      "public/index.html": `<script src="https://cdn.example.com/a.js" integrity="sha384-x" crossorigin="anonymous"></script>`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A09 — security-txt", () => {
  it("next projesinde security.txt yoksa → info", async () => {
    const f = await run(
      securityTxt,
      { "package.json": `{"name":"x"}` },
      { stack: { framework: "next" } },
    );
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
  });
  it("security.txt varsa → temiz", async () => {
    const f = await run(
      securityTxt,
      { "public/.well-known/security.txt": `Contact: mailto:s@x.com` },
      { stack: { framework: "next" } },
    );
    expect(f.length).toBe(0);
  });
});

describe("A02 — secrets-git-history (scanGitDiff)", () => {
  it("catches a committed stripe key and .env", () => {
    const diff = [
      "commit a1b2c3d4e5f6",
      "+++ b/.env",
      '+STRIPE_KEY=sk_test_ABCDEFGH12345678',
      "+++ b/src/config.ts",
      '+const stripe = "sk_test_ABCDEFGH12345678";',
    ].join("\n");
    const hits = scanGitDiff(diff);
    expect(hits.some((h) => h.name === "Committed .env file")).toBe(true);
    expect(hits.some((h) => h.name === "Stripe secret key")).toBe(true);
  });
  it("temiz diff (env.example, process.env) → yakalamaz", () => {
    const diff = [
      "commit a1b2c3d4e5f6",
      "+++ b/.env.example",
      "+STRIPE_KEY=your-key-here",
      "+++ b/src/config.ts",
      "+const stripe = process.env.STRIPE_KEY;",
    ].join("\n");
    const hits = scanGitDiff(diff);
    expect(hits.length).toBe(0);
  });

  // --- FP tightening: do not fire when the right-hand side is not a LITERAL
  it("a decrypt() call (good practice) → not caught (an expression, not a literal)", () => {
    const diff = [
      "commit 8de20ec44f",
      "+++ b/server.ts",
      "+  const token = decrypt(row.token); // K2: decrypt the encrypted token",
    ].join("\n");
    expect(scanGitDiff(diff).length).toBe(0);
  });
  it("slice(7) on a Bearer header → not caught (an expression)", () => {
    const diff = [
      "commit eab24aa880",
      "+++ b/server.ts",
      "+  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';",
    ].join("\n");
    expect(scanGitDiff(diff).length).toBe(0);
  });
  it("data.token / member access → not caught (an identifier)", () => {
    const diff = [
      "commit eab24aa881",
      "+++ b/server.ts",
      "+  const token = data.someLongPropertyName;",
    ].join("\n");
    expect(scanGitDiff(diff).length).toBe(0);
  });
  it("a dummy secret in a test file → not caught", () => {
    const diff = [
      "commit 437f16b24b",
      "+++ b/tests/metaSignedRequest.test.ts",
      "+const SECRET = 'meta-app-secret-cok-gizli';",
    ].join("\n");
    expect(scanGitDiff(diff).length).toBe(0);
  });
  it("a match in markdown documentation → not caught", () => {
    const diff = [
      "commit 0783d87af7",
      "+++ b/SAHIP_AKSIYONU.md",
      "+2. Webhook (for DM/inbox): Callback URL `{BASE_URL}/webhook?token=abc123def456ghi789`",
    ].join("\n");
    expect(scanGitDiff(diff).length).toBe(0);
  });
  it("a dictionary-like dummy (no digits, all lowercase) → not caught", () => {
    const diff = [
      "commit deadbeef01",
      "+++ b/src/config.ts",
      "+const secret = 'meta-app-secret-cok-gizli-degerdir';",
    ].join("\n");
    expect(scanGitDiff(diff).length).toBe(0);
  });

  // --- A REAL secret must STILL be caught (regression guard)
  it("a REAL quoted password literal (in a code file) → caught", () => {
    const diff = [
      "commit e2b0850650",
      "+++ b/scripts/run-sql.mjs",
      '+  password: "besmaf-8gyzwR3kd9Xa2buc",',
    ].join("\n");
    const hits = scanGitDiff(diff);
    expect(hits.some((h) => h.name === "High-entropy literal secret")).toBe(true);
  });
  it("a REAL embedded provider JWT literal → caught", () => {
    const diff = [
      "commit 85d2af79b4",
      "+++ b/scripts/dump-schema.mjs",
      '+  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIn0.abcDEF123ghiJKL456mnoPQR",',
    ].join("\n");
    const hits = scanGitDiff(diff);
    expect(hits.some((h) => h.name === "JWT/service token")).toBe(true);
  });

  // --- JWT role split: anon (public publishable) → drop; service_role → high
  const makeJwt = (role: string): string => {
    const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const p = Buffer.from(JSON.stringify({ role, iss: "supabase" })).toString("base64url");
    return `${h}.${p}.SIGdummy0123456789abcdefABCDEF`;
  };
  it("Supabase anon (role:anon) publishable key → yakalamaz (public)", () => {
    const diff = [
      "commit 6665227402",
      "+++ b/dashboard/scratch/check_db.js",
      `+const anon = "${makeJwt("anon")}";`,
    ].join("\n");
    expect(scanGitDiff(diff).length).toBe(0);
  });
  it("Supabase service_role JWT → yakalar (high)", () => {
    const diff = [
      "commit 6665227403",
      "+++ b/scripts/dump-schema.mjs",
      `+const key = "${makeJwt("service_role")}";`,
    ].join("\n");
    const hits = scanGitDiff(diff);
    expect(hits.some((h) => h.name === "JWT/service token")).toBe(true);
  });
  it("an AIzaSy client key inside google-services.json → not caught (client config)", () => {
    const diff = [
      "commit 5814a1569a",
      "+++ b/mobile/android/app/google-services.json",
      '+      "current_key": "AIzaSyD1234567890abcdefghijklmnopqrstuvw"',
    ].join("\n");
    expect(scanGitDiff(diff).length).toBe(0);
  });
  it("an AIzaSy Google API key in an ordinary .mjs script → caught (not client config)", () => {
    const diff = [
      "commit 5814a1569b",
      "+++ b/seed-products.mjs",
      '+const API_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuvw";',
    ].join("\n");
    const hits = scanGitDiff(diff);
    expect(hits.some((h) => h.name === "Google API key")).toBe(true);
  });
});

describe("A07 — jwt algorithm confusion", () => {
  it("HS256 and RS256 in the same list → finding", async () => {
    const f = await run(jwtWeakVerification, {
      "lib/jwt.ts": `const d = jwt.verify(token, key, { algorithms: ["HS256", "RS256"] });`,
    });
    expect(f.some((x) => x.title.includes("algorithm confusion"))).toBe(true);
  });
});

describe("A07 — spoofable-client-ip (2026-08-24)", () => {
  it("reading X-Forwarded-For in a rate-limit context → high", async () => {
    const f = await run(spoofableClientIp, {
      "auth.py": `
def _istemci_ip():
    xff = request.headers.get('X-Forwarded-For', '')
    return xff.split(',')[0]
def _deneme_hakki(ip):  # brute-force freni
    return GIRIS_AZAMI_DENEME - _giris_denemeleri.get(ip, 0)`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
  // In one project the login brake read x-vercel-forwarded-for first and fell
  // back to XFF ONLY when that was absent. Vercel sets that header on every
  // request → not exploitable in production. Not the same as the raw-XFF hole.
  it("platform header first, XFF fallback → low rather than high", async () => {
    const f = await run(spoofableClientIp, {
      "app/api/auth/route.ts": `export async function POST(request){
  const clientAddress = request.headers.get("x-vercel-forwarded-for")?.trim() || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "local";
  const { limited } = await consumeRateLimit("login", clientAddress, 8, 900000);
  if (limited) return Response.json({ error: "Too many login attempts" }, { status: 429 });
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("low");
    expect(f[0].description).toMatch(/Move the project off that platform/);
  });
  it("BAD: no platform header, raw XFF[0] → high (the real case)", async () => {
    const f = await run(spoofableClientIp, {
      "app/api/auth/route.ts": `export async function POST(request){
  const clientAddress = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "local";
  const { limited } = await consumeRateLimit("login", clientAddress, 8, 900000);
  if (limited) return Response.json({ error: "429" }, { status: 429 });
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
  it("XFF for logging only (no security context) → no finding", async () => {
    const f = await run(spoofableClientIp, {
      "log.py": `ip = request.headers.get('X-Forwarded-For'); logger.info(ip)`,
    });
    expect(f.length).toBe(0);
  });
  it("reading a safe X-Real-IP → low (the two may be mixed up)", async () => {
    const f = await run(spoofableClientIp, {
      "auth.py": `
def _ip():  # rate limit
    return request.headers.get('X-Real-IP') or request.headers.get('X-Forwarded-For','').split(',')[0]`,
    });
    expect(f.length === 0 || f[0].severity === "low").toBe(true);
  });
});

describe("A03 — sql-identifier-injection (2026-08-24)", () => {
  it("a SET column name from a dict key → high", async () => {
    const f = await run(sqlIdentifierInjection, {
      "db.py": `
def update_profile(pid, data):
    fields = []
    for key, val in data.items():
        fields.append(f"{key} = ?")
    conn.execute(f"UPDATE profiles SET {', '.join(fields)} WHERE id = ?", vals)`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
  it("interpolating a code constant (UPPERCASE) → no finding (false positive filtered)", async () => {
    const f = await run(sqlIdentifierInjection, {
      "db.py": `count = conn.execute(f"SELECT COUNT(*) FROM listings WHERE {EV_KOSULU}", par)`,
    });
    expect(f.length).toBe(0);
  });
  it("a condition variable assembled in code → no finding", async () => {
    const f = await run(sqlIdentifierInjection, {
      "db.py": `rows = conn.execute(f"SELECT * FROM t l WHERE {kosul}{ara_sql}", par)`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A04 — sqlite-no-busy-timeout (2026-08-24)", () => {
  it("a writing background job with no busy_timeout → medium", async () => {
    const f = await run(sqliteNoBusyTimeout, {
      "scraper.py": `
import sqlite3
def kaydet():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO comps VALUES (?)", (x,))`,
      "cron.txt": "OnCalendar=*-*-* 04:00",
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("busy_timeout is set → no finding", async () => {
    const f = await run(sqliteNoBusyTimeout, {
      "db.py": `
import sqlite3
conn = sqlite3.connect(DB_PATH)
conn.execute("PRAGMA busy_timeout=5000")
conn.execute("INSERT INTO t VALUES (1)")`,
    });
    expect(f.length).toBe(0);
  });
  it("a read-only (SELECT-only) tool → no finding", async () => {
    const f = await run(sqliteNoBusyTimeout, {
      "rapor.py": `
import sqlite3
import sys
sys.path.insert(0, ".")
conn = sqlite3.connect(DB_PATH)
n = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]`,
    });
    expect(f.length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────
// Classes found during a manual audit: an unbounded paid loop, tracked backup
// leftovers, test/schema divergence, FK cascade disabled, an unguarded JSON
// parse. Each one: detection plus a negative case.
// ─────────────────────────────────────────────────────────────────────
import { unboundedPaidLoop } from "../src/static/unbounded-paid-loop.js";
import { backupCruftTracked } from "../src/static/backup-cruft-tracked.js";
import { testSchemaDivergence } from "../src/static/test-schema-divergence.js";
import { fkCascadeOff } from "../src/static/fk-cascade-off.js";
import { unguardedJsonParse } from "../src/static/unguarded-json-parse.js";

describe("A04 — unbounded-paid-loop", () => {
  it("a paid API in an uncapped loop → medium", async () => {
    const f = await run(unboundedPaidLoop, {
      "worker/gen.py": `def isle(rows):
    for row in rows:
        openai.chat.completions.create(model="x", messages=row)

if __name__ == "__main__":
    isle([])
`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("the loop is bounded with slice → NO finding", async () => {
    const f = await run(unboundedPaidLoop, {
      "worker/gen.py": `def isle(rows):
    for row in rows[:50]:
        openai.chat.completions.create(model="x", messages=row)
`,
    });
    expect(f.length).toBe(0);
  });
  it("a single paid API call OUTSIDE a loop → NO finding", async () => {
    const f = await run(unboundedPaidLoop, {
      "worker/gen.py": `def isle(row):
    return openai.chat.completions.create(model="x", messages=row)
`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A05 — backup-cruft-tracked", () => {
  it("a tracked *.bak file not covered by gitignore → medium", async () => {
    const f = await run(backupCruftTracked, {
      "app.py": "print(1)",
      ".gitignore": "__pycache__/\n*.pyc",
      "Alfa.db.yedek-20260821": "BINARY",
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("no leftovers and gitignore covers *.bak → NO finding", async () => {
    const f = await run(backupCruftTracked, {
      "app.py": "print(1)",
      ".gitignore": "*.yedek\n*.yedek-*\n*.bak\nvenv.eski*/",
    });
    expect(f.length).toBe(0);
  });
});

describe("A08 — test-schema-divergence", () => {
  it("conftest builds its own CREATE TABLE and production has init_db → finding", async () => {
    const f = await run(testSchemaDivergence, {
      "database/models.py": "def init_db():\n    pass\n",
      "tests/conftest.py": "def kur(c):\n    c.execute('CREATE TABLE listings (id INTEGER)')\n",
    });
    expect(f.length).toBe(1);
  });
  it("conftest calls production's init_db (no copied schema) → NO finding", async () => {
    const f = await run(testSchemaDivergence, {
      "database/models.py": "def init_db():\n    pass\n",
      "tests/conftest.py": "from database.models import init_db\ndef kur():\n    init_db()\n",
    });
    expect(f.length).toBe(0);
  });
});

describe("A04 — fk-cascade-off", () => {
  it("CASCADE declared and the foreign_keys PRAGMA is never enabled → medium", async () => {
    const f = await run(fkCascadeOff, {
      "database/models.py": `import sqlite3
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE child (id INTEGER, pid INTEGER REFERENCES parent(id) ON DELETE CASCADE)")
`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("PRAGMA foreign_keys=ON is enabled somewhere → NO finding", async () => {
    const f = await run(fkCascadeOff, {
      "database/models.py": `import sqlite3
def baglan():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
def init_db():
    conn = baglan()
    conn.execute("CREATE TABLE child (id INTEGER, pid INTEGER REFERENCES parent(id) ON DELETE CASCADE)")
`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A04 — unguarded-json-parse", () => {
  it("json.loads(variable) with no try → low", async () => {
    const f = await run(unguardedJsonParse, {
      "scraper/oku.py": `def parse(text):
    data = json.loads(text)
    return data
`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("low");
  });
  it("a large outer try block (a retry loop) wraps the json.loads → NO finding", async () => {
    const f = await run(unguardedJsonParse, {
      "scraper/oku.py": `def scrape(url):
    for attempt in range(6):
        try:
            resp = get(url)
            body = resp.text
            head = body[:10]
            more = head + "x"
            data = json.loads(body)
            return data
        except Exception as e:
            continue
`,
    });
    expect(f.length).toBe(0);
  });
  it("sabit literal json.loads('{}') → bulgu YOK", async () => {
    const f = await run(unguardedJsonParse, {
      "scraper/oku.py": `def defaults():
    return json.loads('{}')
`,
    });
    expect(f.length).toBe(0);
  });
});

describe("a01 — service_role: documentation is not code", () => {
  it("CLEAN: the role NAME inside .md produces no finding", async () => {
    // Once `.md` started being scanned, every sentence about "service_role" in the
    // documentation became a finding. There is no key there, just the role's name.
    const { supabaseServiceRole } = await import("../src/static/supabase-service-role.js");
    const f = supabaseServiceRole.run(makeCtx({
      "db/README.md": "Supabase ships with the `anon`, `authenticated` and `service_role` roles.",
    })) as Array<unknown>;
    expect(f.length).toBe(0);
  });

  it("BAD: real service_role usage in code is still caught", async () => {
    const { supabaseServiceRole } = await import("../src/static/supabase-service-role.js");
    const f = supabaseServiceRole.run(makeCtx({
      "lib/admin.ts": `const sb = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    })) as Array<unknown>;
    expect(f.length).toBeGreaterThan(0);
  });
});

import { swallowedDdlError } from "../src/static/swallowed-ddl-error.js";

describe("A09 — swallowed-ddl-error", () => {
  it("a bare except: pass wrapping an ALTER → finding", async () => {
    const f = await run(swallowedDdlError, {
      "database/models.py": `def init_db(cur):
    try:
        cur.execute("ALTER TABLE listings ADD COLUMN description TEXT")
    except:
        pass
`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("low");
  });
  it("except Exception: pass counts as swallowing too → finding", async () => {
    const f = await run(swallowedDdlError, {
      "db.py": `def m(cur):
    try:
        cur.execute("CREATE INDEX idx ON t(x)")
    except Exception:
        pass
`,
    });
    expect(f.length).toBe(1);
  });
  it("a narrowed except (OperationalError + raise) → NO finding", async () => {
    const f = await run(swallowedDdlError, {
      "database/models.py": `import sqlite3
def _sutun_ekle(cur):
    try:
        cur.execute("ALTER TABLE listings ADD COLUMN c TEXT")
    except sqlite3.OperationalError as e:
        if "duplicate column" not in str(e).lower():
            raise
`,
    });
    expect(f.length).toBe(0);
  });
  it("DDL olmayan try/except: pass → bulgu YOK", async () => {
    const f = await run(swallowedDdlError, {
      "svc.py": `def f(x):
    try:
        y = int(x)
    except:
        pass
    cur.execute("ALTER TABLE t ADD COLUMN c TEXT")
`,
    });
    // the ALTER is in the file but the except does NOT wrap it (another function) -> no finding
    expect(f.length).toBe(0);
  });
});

import { checkThenActUpsert } from "../src/static/check-then-act-upsert.js";

describe("A04 — check-then-act-upsert", () => {
  it("SELECT-exists + INSERT + UPDATE on the same table, no upsert → finding", async () => {
    const f = await run(checkThenActUpsert, {
      "db.py": `def kaydet(cur, id, durum):
    row = cur.execute("SELECT id FROM ilan_sonuc WHERE id = ?", (id,)).fetchone()
    if row:
        cur.execute("UPDATE ilan_sonuc SET durum = ? WHERE id = ?", (durum, id))
    else:
        cur.execute("INSERT INTO ilan_sonuc (id, durum) VALUES (?, ?)", (id, durum))
`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("low");
  });
  it("ON CONFLICT upsert (atomik) → bulgu YOK", async () => {
    const f = await run(checkThenActUpsert, {
      "db.py": `def kaydet(cur, id, durum):
    cur.execute("SELECT id FROM ilan_sonuc WHERE id = ?", (id,))
    cur.execute("INSERT INTO ilan_sonuc (id, durum) VALUES (?, ?) "
                "ON CONFLICT(id) DO UPDATE SET durum = excluded.durum", (id, durum))
`,
    });
    expect(f.length).toBe(0);
  });
  it("INSERT only (no UPDATE/SELECT) → NO finding", async () => {
    const f = await run(checkThenActUpsert, {
      "db.py": `def ekle(cur, id):
    cur.execute("INSERT INTO log (id) VALUES (?)", (id,))
`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A04 — check-then-act-upsert (Faz 1 kesinlik)", () => {
  it("SELECT/UPDATE in a DIFFERENT function from the INSERT → NO finding (cross-function)", async () => {
    const f = await run(checkThenActUpsert, {
      "db.py": `def create_row(cur, x):
    cur.execute("INSERT INTO t (x) VALUES (?)", (x,))

def get_row(cur, x):
    return cur.execute("SELECT id FROM t WHERE x = ?", (x,)).fetchone()

def update_row(cur, x):
    cur.execute("UPDATE t SET x = ? WHERE id = 1", (x,))
`,
    });
    expect(f.length).toBe(0);
  });
  it("a try wrapping the INSERT with except IntegrityError → NO finding (the race falls back to an update)", async () => {
    const f = await run(checkThenActUpsert, {
      "db.py": `import sqlite3
def upsert(cur, x):
    row = cur.execute("SELECT id FROM t WHERE x = ?", (x,)).fetchone()
    if row:
        cur.execute("UPDATE t SET x = ? WHERE id = ?", (x, row[0]))
    else:
        try:
            cur.execute("INSERT INTO t (x) VALUES (?)", (x,))
        except sqlite3.IntegrityError:
            cur.execute("UPDATE t SET x = ? WHERE x = ?", (x, x))
`,
    });
    expect(f.length).toBe(0);
  });
  it("SELECT→UPDATE/INSERT in the same function with no guard → still a finding", async () => {
    const f = await run(checkThenActUpsert, {
      "db.py": `def upsert(cur, x):
    row = cur.execute("SELECT id FROM t WHERE x = ?", (x,)).fetchone()
    if row:
        cur.execute("UPDATE t SET x = ? WHERE id = ?", (x, row[0]))
    else:
        cur.execute("INSERT INTO t (x) VALUES (?)", (x,))
`,
    });
    expect(f.length).toBe(1);
  });
});

describe("A04 — unbounded-paid-loop (dead module)", () => {
  it("no import and no __main__ (a dead module) → NO finding", async () => {
    const f = await run(unboundedPaidLoop, {
      "scraper/eski.py": `def isle(rows):
    for row in rows:
        anthropic.messages.create(model="x", messages=row)
`,
      "scraper/canli.py": `from scraper.baska import x\nprint(x)`,
    });
    expect(f.length).toBe(0);
  });
  it("__main__ IS present (a systemd worker) → still a finding (no false negative)", async () => {
    const f = await run(unboundedPaidLoop, {
      "worker.py": `def isle(rows):
    for row in rows:
        anthropic.messages.create(model="x", messages=row)

if __name__ == "__main__":
    isle([])
`,
    });
    expect(f.length).toBe(1);
  });
  it("another file DOES import it → still a finding", async () => {
    const f = await run(unboundedPaidLoop, {
      "lib/gen.py": `def isle(rows):
    for row in rows:
        openai.chat.completions.create(model="x", messages=row)
`,
      "app.py": `from lib.gen import isle\nisle([])`,
    });
    expect(f.length).toBe(1);
  });
});

import { inmemoryRatelimitServerless } from "../src/static/inmemory-ratelimit-serverless.js";

describe("A04 — inmemory-ratelimit-serverless", () => {
  it("a Next project with a module-level Map rate limit → finding", async () => {
    const f = await run(inmemoryRatelimitServerless, {
      "next.config.js": "module.exports = {}",
      "lib/rate-limit.ts": `const attempts = new Map<string, number>();
export function rateLimit(ip: string) {
  const n = (attempts.get(ip) ?? 0) + 1;
  attempts.set(ip, n);
  if (n > 5) return { ok: false, status: 429 };
  return { ok: true };
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("it uses Upstash/Redis → NO finding", async () => {
    const f = await run(inmemoryRatelimitServerless, {
      "next.config.js": "module.exports = {}",
      "lib/rate-limit.ts": `import { Ratelimit } from "@upstash/ratelimit";
import { kv } from "@vercel/kv";
const ratelimit = new Ratelimit({ redis: kv, limiter: Ratelimit.slidingWindow(5, "60 s") });
export async function rateLimit(ip: string) { return ratelimit.limit(ip); }`,
    });
    expect(f.length).toBe(0);
  });
  it("NOT serverless (no Next/Vercel) → NO finding", async () => {
    const f = await run(inmemoryRatelimitServerless, {
      "server.js": `const attempts = new Map();
function rateLimit(ip){ const n=(attempts.get(ip)||0)+1; attempts.set(ip,n); if(n>5) return {status:429}; }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A04 — inmemory-ratelimit-serverless (comment false-negative regression)", () => {
  it("new Map in code plus 'should move to Upstash' IN A COMMENT → still a finding", async () => {
    // A real case: the word 'Upstash' in a comment made a raw text search believe
    // a durable store existed, and the real Map store was missed.
    const f = await run(inmemoryRatelimitServerless, {
      "next.config.js": "module.exports = {}",
      "src/lib/rate-limit.ts": `/**
 * Basit in-memory rate limiter.
 * Note: single-instance only. Should move to Upstash Redis for production.
 */
const store = new Map<string, number>();
export function rateLimit(ip: string) {
  const n = (store.get(ip) ?? 0) + 1;
  store.set(ip, n);
  return n <= 5;
}`,
    });
    expect(f.length).toBe(1);
  });
});

describe("A01 — api-route-auth-missing (Faz 2 kesinlik)", () => {
  it("a multi-tenant resolver (resolves the client from a cookie) → counts as auth, NO finding", async () => {
    const f = await run(apiRouteAuthMissing, {
      "src/lib/client-context.ts": `export function readActiveClientCookie(req: Request): string | null {
  const header = req.headers.get("cookie") || "";
  return header.includes("ac=") ? "x" : null;
}
export async function resolveActiveClientId(req: Request): Promise<string | null> {
  const c = readActiveClientCookie(req);
  return c ? c : null;
}`,
      "src/app/api/campaigns/route.ts": `import { resolveActiveClientId } from "@/lib/client-context";
export async function GET(req){ const clientId = await resolveActiveClientId(req); if(!clientId) return Response.json([]); return Response.json(await db.select().from(campaigns).where(eq(campaigns.clientId, clientId))); }`,
    });
    expect(f.length).toBe(0);
  });
  it("a public/track/unsubscribe route → NO finding (public by design)", async () => {
    const f = await run(apiRouteAuthMissing, {
      "src/app/api/track/audit/[slug]/route.ts": `export async function GET(req){ const data = await db.select().from(audits).findFirst(); return Response.json(data); }`,
    });
    expect(f.length).toBe(0);
  });
  it("requireOwner ile korunan route → bulgu YOK", async () => {
    const f = await run(apiRouteAuthMissing, {
      "src/app/api/team/route.ts": `import { requireOwner } from "@/lib/team-auth";
export async function GET(req){ if(!(await requireOwner(req))) return Response.json({e:1},{status:403}); return Response.json(await db.select().from(team)); }`,
    });
    expect(f.length).toBe(0);
  });
  it("REGRESSION: a genuinely unauthenticated READ route → still reported (inventory)", async () => {
    // Note: the level went from low to info. An open read with no identity is
    // usually a design choice; it is listed as inventory rather than a finding. But it does NOT go silent.
    const f = await run(apiRouteAuthMissing, {
      "src/app/api/clients/route.ts": `export async function GET(){ const data = await db.select().from(clients); return Response.json(data); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
  });
  it("REGRESSION: a genuinely unauthenticated MUTATION route → high finding", async () => {
    const f = await run(apiRouteAuthMissing, {
      "src/app/api/clients/[id]/route.ts": `export async function PUT(req){ const b = await req.json(); await db.update(clients).set(b).where(eq(clients.id, b.id)); return Response.json({ok:1}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
});

describe("A08/A05 — webhook + CORS (Faz 2 kesinlik)", () => {
  it("an SES webhook verified with verifySnsSignature → NO finding", async () => {
    const f = await run(webhookSignature, {
      "src/app/api/webhook/ses/route.ts": `import { verifySnsSignature } from "@/lib/sns";
export async function POST(req){ const m = await req.json(); if(!verifySnsSignature(m)) return new Response("bad",{status:400}); return Response.json({ok:1}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("origin reflection that passed an allowlist → NO finding (safe CORS)", async () => {
    const f = await run(corsWildcard, {
      "server.ts": `const ALLOWED_ORIGINS = ["https://app.x.com"];
if (origin && ALLOWED_ORIGINS.includes(origin)) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Access-Control-Allow-Credentials','true'); }`,
    });
    expect(f.length).toBe(0);
  });
  it("REGRESYON: wildcard * + credentials → hâlâ bulgu", async () => {
    const f = await run(corsWildcard, {
      "server.ts": `res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Credentials', 'true');`,
    });
    expect(f.length).toBe(1);
  });
});

describe("A07 — spoofable-client-ip (the safe pattern)", () => {
  it("x-real-ip first plus XFF rightmost (trustedIp) → NO finding (the correct pattern)", async () => {
    const f = await run(spoofableClientIp, {
      "lib/rate-limit.ts": `export function key(req, scope){
  const rateLimit = true; // security context
  const real = req.headers.get("x-real-ip");
  const parts = (req.headers.get("x-forwarded-for") ?? "").split(",").map(s=>s.trim()).filter(Boolean);
  const ip = real || (parts.length ? parts[parts.length-1] : "local");
  return scope+":"+ip;
}`,
    });
    expect(f.length).toBe(0);
  });
  it("XFF leftmost [0] (forgeable) plus a security context → still a finding", async () => {
    const f = await run(spoofableClientIp, {
      "lib/rate-limit.ts": `export function key(req, scope){
  const rateLimit = true;
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return scope+":"+ip;
}`,
    });
    expect(f.length).toBe(1);
  });
});

describe("A01 — api-auth (middleware/proxy protection)", () => {
  it("proxy.ts /api'yi AUTH_COOKIE ile koruyorsa handler'da auth olmasa da → bulgu YOK", async () => {
    const f = await run(apiRouteAuthMissing, {
      "src/proxy.ts": `import { AUTH_COOKIE } from "@/lib/auth";
const PROTECTED = ["/api/clients","/api/team"];
export function proxy(req){ const t = req.cookies.get(AUTH_COOKIE); if(!t) return Response.redirect("/login"); }
export const config = { matcher: ["/((?!_next).*)"] };`,
      "src/app/api/clients/route.ts": `import { db } from "@/db";
export async function GET(){ return Response.json(await db.select().from(clients)); }`,
    });
    expect(f.length).toBe(0);
  });
  it("middleware YOKSA auth'suz route → hâlâ bulgu", async () => {
    const f = await run(apiRouteAuthMissing, {
      "src/app/api/clients/route.ts": `import { db } from "@/db";
export async function PUT(req){ const b = await req.json(); await db.update(clients).set(b); return Response.json({ok:1}); }`,
    });
    expect(f.length).toBe(1);
  });
});

describe("A07/A08 — crm desenleri (Faz 2 kesinlik)", () => {
  it("x-vercel-forwarded-for[0] plus x-real-ip (Vercel, safe) → NO spoofable finding", async () => {
    const f = await run(spoofableClientIp, {
      "lib/rate-limit.ts": `export function clientIp(h){
  const rateLimit = true;
  const v = h.get("x-vercel-forwarded-for")?.split(",")[0]?.trim(); if(v) return v;
  const r = h.get("x-real-ip")?.trim(); if(r) return r;
  const parts = (h.get("x-forwarded-for")??"").split(",").map(s=>s.trim()).filter(Boolean);
  return parts.length ? parts[parts.length-1] : "unknown";
}`,
    });
    expect(f.length).toBe(0);
  });
  it("bearer-secret webhook auth (isWebhookAuthorized) → unverified-webhook bulgu YOK", async () => {
    const f = await run(webhookSignature, {
      "app/api/whatsapp/webhook/route.ts": `function isWebhookAuthorized(req){
  const s = process.env.WHATSAPP_WEBHOOK_SECRET; if(!s) return false;
  return req.headers.get("x-webhook-secret") === s;
}
export async function POST(req){ if(!isWebhookAuthorized(req)) return Response.json({e:1},{status:401}); return Response.json({ok:1}); }`,
    });
    expect(f.length).toBe(0);
  });
})

/**
 * One run produced 8 SSRF findings; in 7 of them THE HOST WAS FIXED (USGS_BASE,
 * api.neverbounce.com, graph.facebook.com, ${BASE}/einvoice/...). Sorgu
 * putting user input in a query parameter does not send the request elsewhere.
 * In the single real finding the target was a function parameter.
 */
describe("A10 — ssrf: host sabitse bulgu yok", () => {
  it("CLEAN: the template's host is written out in full", async () => {
    const f = await run(ssrf, {
      "src/lib/email-validation.ts": `export async function check(email: string) {
  const url = \`https://api.neverbounce.com/v4/single/check?key=\${encodeURIComponent(nb)}&email=\${encodeURIComponent(email)}\`;
  const res = await fetch(url);
  return res.ok;
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: the host comes from a module constant", async () => {
    const f = await run(ssrf, {
      "src/lib/seismicity.ts": `const USGS_BASE = "https://earthquake.usgs.gov/fdsnws/event/1/query";
export async function ara(params: URLSearchParams, req: Request) {
  const url = \`\${USGS_BASE}?\${params.toString()}\`;
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  return res.json();
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a fixed base in the `${BASE}/path` shape", async () => {
    const f = await run(ssrf, {
      "lib/nes/client.ts": `const BASE = "https://api.nes.com.tr";
export async function gonder(req: Request, formData: FormData) {
  const res = await fetch(\`\${BASE}/einvoice/v1/uploads/document\`, { method: "POST", body: formData });
  return res.status;
}`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: the target is a variable from outside → the finding stands", async () => {
    const f = await run(ssrf, {
      "lib/seo/runner.ts": `export function ctx(request: Request) {
  return {
    async probe(target: string) {
      const res = await fetch(target, { method: "GET", redirect: "manual" });
      return res.status;
    },
  };
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("CLEAN: `process.env.X || \"https://...\"` is the operator's base", async () => {
    const f = await run(ssrf, {
      "lib/nes/client.ts": `const BASE = process.env.NES_API_URL || "https://apitest.nes.com.tr";
export async function gonder(req: Request, formData: FormData) {
  const res = await fetch(\`\${BASE}/einvoice/v1/uploads/document\`, { method: "POST", body: formData });
  return res.status;
}`,
    });
    expect(f.length).toBe(0);
  });

  it("INTERMEDIATE: the target is only a parameter → low plus 'audit the call sites'", async () => {
    const f = await run(ssrf, {
      "lib/seo/server.ts": `export async function measureResponseTime(url: string, timeoutMs = 12000) {
  const ac = new AbortController();
  await fetch(url, { redirect: "follow", signal: ac.signal });
  return Date.now();
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("low");
    expect(f[0].title).toMatch(/SSRF carrier/);
  });

  it("CLEAN: a hostname validated by regex counts as an allowlist", async () => {
    const f = await run(ssrf, {
      "src/lib/sns.ts": `function isValidCertUrl(raw: string) {
  const url = new URL(raw);
  if (url.protocol !== "https:") return false;
  const host = url.hostname.toLowerCase();
  return /^sns\\.[a-z0-9-]+\\.amazonaws\\.com$/.test(host);
}
async function fetchCert(certUrl: string): Promise<string> {
  const res = await fetch(certUrl);
  return res.text();
}`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: the host derives directly from the request → finding", async () => {
    const f = await run(ssrf, {
      "app/api/proxy/route.ts": `export async function GET(req: Request) {
  const targetUrl = new URL(req.url).searchParams.get("u");
  const res = await fetch(targetUrl);
  return Response.json({ status: res.status });
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});
