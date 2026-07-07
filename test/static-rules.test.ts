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

async function run(
  rule: StaticRule,
  files: Record<string, string>,
  overrides?: Parameters<typeof makeCtx>[1],
): Promise<Finding[]> {
  return Promise.resolve(rule.run(makeCtx(files, overrides)));
}

describe("A01 — api-route-auth-missing", () => {
  it("auth'suz DB YAZAN (mutation) route → high olası", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/orders/route.ts": `export async function POST(req){ const b = await req.json(); await db.orders.create({ data: b }); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].confidence).toBe("olası");
  });
  it("auth'suz DB OKUYAN (GET) route → medium (public veri olabilir)", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/orders/route.ts": `export async function GET(req){ const data = await db.orders.findMany(); return Response.json(data); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("DB'ye dokunmayan public route (og görsel) → bulgu yok", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/og/route.tsx": `import { ImageResponse } from "next/og"; export async function GET(req){ return new ImageResponse(<div>hi</div>); }`,
    });
    expect(f.length).toBe(0);
  });
  it("imza doğrulamalı webhook → bulgu yok", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/webhook/route.ts": `export async function POST(req){ const sig = req.headers.get("stripe-signature"); const event = stripe.webhooks.constructEvent(body, sig, secret); await db.order.update({}); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("auth içeren route'ta bulgu üretmez", async () => {
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
  it("ownership'siz params.id sorgusunda bulgu üretir", async () => {
    const f = await run(idorDirectObject, {
      "app/api/doc/route.ts": `export async function GET(req,{params}){ const doc = await supabase.from("docs").select().eq("id", params.id).single(); return Response.json(doc); }`,
    });
    expect(f.length).toBe(1);
  });
  it("user_id filtresi varsa bulgu üretmez", async () => {
    const f = await run(idorDirectObject, {
      "app/api/doc/route.ts": `export async function GET(req,{params}){ const doc = await supabase.from("docs").select().eq("id", params.id).eq("user_id", session.user.id).single(); return doc; }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A01 — supabase-service-role", () => {
  it("service_role kullanımında bulgu, client dosyada critical", async () => {
    const f = await run(supabaseServiceRole, {
      "components/Admin.tsx": `"use client"; const c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("critical");
  });
  it("temiz anon key ile bulgu üretmez", async () => {
    const f = await run(supabaseServiceRole, {
      "lib/db.ts": `const c = createClient(url, process.env.SUPABASE_ANON_KEY);`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A02 — hardcoded-secrets", () => {
  it("Stripe live key'i critical + kesin yakalar", async () => {
    const f = await run(hardcodedSecrets, {
      "lib/pay.ts": `const key = "sk_***MASKED***";`,
    });
    expect(f.some((x) => x.severity === "critical")).toBe(true);
    // engine confidence'ı stamp'liyor; kural varsayılanı kesin
    expect(hardcodedSecrets.confidence).toBe("kesin");
  });
  it("process.env kullanımında bulgu üretmez", async () => {
    const f = await run(hardcodedSecrets, {
      "lib/pay.ts": `const key = process.env.STRIPE_SECRET_KEY; const apiKey = "your-api-key-here";`,
    });
    expect(f.length).toBe(0);
  });
  it("gitignore'lanmış .env.local'daki sır → kod-gömülü olarak RAPORLANMAZ", async () => {
    const f = await run(
      hardcodedSecrets,
      { ".env.local": `STRIPE_SECRET_KEY=sk_***MASKED***` },
      { tracked: [] }, // izlenmiyor (gitignore'lanmış)
    );
    expect(f.length).toBe(0);
  });
  it("git'e izlenen (commit'lenmiş) .env'deki sır → kod-gömülü olarak yakalanır", async () => {
    const f = await run(
      hardcodedSecrets,
      { ".env": `STRIPE_SECRET_KEY=sk_***MASKED***` },
      { tracked: [".env"] },
    );
    expect(f.some((x) => x.severity === "critical")).toBe(true);
  });
});

describe("A02 — env-committed", () => {
  it("git'e izlenen (commit'lenmiş) .env → high kesin", async () => {
    const f = await run(
      envCommitted,
      {
        ".env": `DATABASE_URL=postgres://user:realpassword@host:5432/db\nSTRIPE_KEY=sk_***MASKED***`,
        "package.json": `{"name":"x"}`,
        ".gitignore": `node_modules/`,
      },
      { tracked: [".env", "package.json", ".gitignore"] },
    );
    const high = f.find((x) => x.severity === "high");
    expect(high).toBeTruthy();
    expect(high!.title).toContain("git'e commit edilmiş");
    expect(high!.confidence).toBe("kesin");
  });
  it("gitignore'lanmış (izlenmeyen) .env.local → high ÜRETMEZ (info)", async () => {
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
  it(".gitignore .env içeriyorsa ve dosya yoksa high üretmez", async () => {
    const f = await run(envCommitted, {
      "package.json": `{"name":"x"}`,
      ".gitignore": `node_modules/\n.env*`,
    });
    expect(f.filter((x) => x.severity === "high").length).toBe(0);
  });
});

describe("A02 — next-public-secret", () => {
  it("NEXT_PUBLIC_ altında SERVICE_ROLE critical", async () => {
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
  it("parola için md5 → bulgu", async () => {
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
    expect(f[0].confidence).toBe("kesin");
    expect(f[0].severity).toBe("high");
  });
  it("child_process sabit/araç kullanımı → low olası (HIGH değil)", async () => {
    const f = await run(dangerousEval, {
      "scripts/build.ts": `import { execSync } from "child_process"; execSync("tsc -p tsconfig.json");`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
    const cp = f.find((x) => x.title.includes("child_process"));
    expect(cp!.severity).toBe("low");
    expect(cp!.confidence).toBe("olası");
  });
  it("child_process kullanıcı girdisiyle → high", async () => {
    const f = await run(dangerousEval, {
      "app/api/run/route.ts": `import { exec } from "child_process"; export async function POST(req){ const { cmd } = await req.json(); exec(\`convert \${cmd}\`); }`,
    });
    const cp = f.find((x) => x.title.includes("child_process"));
    expect(cp!.severity).toBe("high");
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
  it("tüm headerlar tanımlıysa temiz", async () => {
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
  it("vite projesinde çalışmaz", async () => {
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
  it("kullanıcı url'ine fetch → bulgu", async () => {
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
  it("Prisma'da tc_kimlik String → high bulgu", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "prisma/schema.prisma": `model User {\n  id       Int    @id\n  tc_kimlik String\n  email    String\n}`,
    });
    expect(f.some((x) => x.severity === "high")).toBe(true);
    expect(f[0].cwe).toBe("CWE-311");
  });
  it("SQL'de ssn varchar → bulgu", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "migrations/001.sql": `CREATE TABLE patients (\n  id serial primary key,\n  ssn varchar(11) not null,\n  cvv text\n);`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
  it("kod içinde access_token DB'ye düz yazılıyor → bulgu", async () => {
    const f = await run(sensitiveDataPlaintext, {
      "lib/oauth.ts": `await prisma.account.create({ data: { access_token: token, userId } });`,
    });
    expect(f.some((x) => x.title.includes("Token/secret"))).toBe(true);
  });
  it("bytea/pgp_sym_encrypt ile şifreli → temiz", async () => {
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
  it("RLS açılmamış public tablo → high", async () => {
    const f = await run(missingRls, {
      "supabase/migrations/001.sql": `create table public.profiles ( id uuid primary key, bio text );`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
  it("RLS açık ama policy yok → medium", async () => {
    const f = await run(missingRls, {
      "supabase/migrations/001.sql": `create table public.notes ( id uuid primary key );\nalter table public.notes enable row level security;`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
  it("RLS + policy → temiz", async () => {
    const f = await run(missingRls, {
      "supabase/migrations/001.sql": `create table public.notes ( id uuid primary key, user_id uuid );\nalter table public.notes enable row level security;\ncreate policy "owner" on public.notes for select using (auth.uid() = user_id);`,
    });
    expect(f.length).toBe(0);
  });
  it("auth şeması tablosu → yok sayılır", async () => {
    const f = await run(missingRls, {
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
  it("sıradan alanlar → temiz", async () => {
    const f = await run(kvkkSpecialCategory, {
      "prisma/schema.prisma": `model User { id Int @id\n  name String\n}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A01 — open-redirect", () => {
  it("searchParams hedefi doğrulanmadan redirect → bulgu", async () => {
    const f = await run(openRedirect, {
      "app/api/go/route.ts": `export function GET(req){ const next = new URL(req.url).searchParams.get("next"); return redirect(next); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe("CWE-601");
  });
  it("startsWith('/') doğrulaması → temiz", async () => {
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
  it("CSRF token doğrulaması → temiz", async () => {
    const f = await run(csrfMissing, {
      "app/api/profile/route.ts": `import { cookies } from "next/headers"; export async function POST(req){ const c = cookies(); if(req.headers.get("x-csrf-token")!==csrfToken) return new Response("no",{status:403}); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
  it("Bearer token API → CSRF'e kapalı, temiz", async () => {
    const f = await run(csrfMissing, {
      "app/api/profile/route.ts": `export async function POST(req){ const auth = req.headers.get("authorization"); const session = getServerSession(); return Response.json({ok:true}); }`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A01 — mass-assignment", () => {
  it("req.body doğrudan update'e → bulgu", async () => {
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
  it("şema ile doğrulanmış alanlar → temiz", async () => {
    const f = await run(massAssignment, {
      "app/api/u/route.ts": `export async function PUT(req){ const input = schema.parse(await req.json()); return prisma.user.update({ where:{id}, data: { name: input.name } }); }`,
    });
    expect(f.length).toBe(0);
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
  it("commit'lenmiş stripe key ve .env → yakalar", () => {
    const diff = [
      "commit a1b2c3d4e5f6",
      "+++ b/.env",
      '+STRIPE_KEY=sk_***MASKED***',
      "+++ b/src/config.ts",
      '+const stripe = "sk_***MASKED***";',
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
});

describe("A07 — jwt algorithm confusion", () => {
  it("HS256 + RS256 aynı listede → bulgu", async () => {
    const f = await run(jwtWeakVerification, {
      "lib/jwt.ts": `const d = jwt.verify(token, key, { algorithms: ["HS256", "RS256"] });`,
    });
    expect(f.some((x) => x.title.includes("karışıklığı"))).toBe(true);
  });
});
