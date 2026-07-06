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

async function run(
  rule: StaticRule,
  files: Record<string, string>,
  overrides?: Parameters<typeof makeCtx>[1],
): Promise<Finding[]> {
  return Promise.resolve(rule.run(makeCtx(files, overrides)));
}

describe("A01 — api-route-auth-missing", () => {
  it("auth kontrolü olmayan route'ta bulgu üretir", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/orders/route.ts": `export async function GET(req){ const data = await db.orders.findMany(); return Response.json(data); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
  it("auth içeren route'ta bulgu üretmez", async () => {
    const f = await run(apiRouteAuthMissing, {
      "app/api/orders/route.ts": `import { auth } from "@clerk/nextjs";
export async function GET(req){ const { userId } = auth(); if(!userId) return new Response("no",{status:401}); return Response.json([]); }`,
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
  it("Stripe live key'i critical yakalar", async () => {
    const f = await run(hardcodedSecrets, {
      "lib/pay.ts": `const key = "sk_***MASKED***";`,
    });
    expect(f.some((x) => x.severity === "critical")).toBe(true);
  });
  it("process.env kullanımında bulgu üretmez", async () => {
    const f = await run(hardcodedSecrets, {
      "lib/pay.ts": `const key = process.env.STRIPE_SECRET_KEY; const apiKey = "your-api-key-here";`,
    });
    expect(f.length).toBe(0);
  });
});

describe("A02 — env-committed", () => {
  it("gerçek değerli .env + gitignore yok → bulgu", async () => {
    const f = await run(envCommitted, {
      ".env": `DATABASE_URL=postgres://user:realpassword@host:5432/db\nSTRIPE_KEY=sk_***MASKED***`,
      "package.json": `{"name":"x"}`,
      ".gitignore": `node_modules/`,
    });
    expect(f.some((x) => x.severity === "high")).toBe(true);
  });
  it(".gitignore .env içeriyorsa high üretmez", async () => {
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
