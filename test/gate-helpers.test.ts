import { describe, it, expect } from "vitest";
import { collectDogrulamaHelperlari } from "../src/core/gate-helpers.js";
import { webhookSignature } from "../src/static/webhook-signature.js";
import { makeCtx } from "./helpers.js";

describe("gate-helpers — güvenlik kapısı keşfi", () => {
  it("gövde-sinyalli doğrulama helper'ını keşfeder (fail-closed secret karşılaştırması)", () => {
    const ctx = makeCtx({
      "lib/webhook-guvenlik.ts": `export function isWebhookAuthorized(req: Request): boolean {\n  const secret = process.env.WHATSAPP_WEBHOOK_SECRET?.trim();\n  if (!secret) return false;\n  const header = req.headers.get("x-webhook-secret");\n  return header === secret;\n}`,
    });
    const helpers = collectDogrulamaHelperlari(ctx);
    expect(helpers.has("isWebhookAuthorized")).toBe(true);
  });

  it("webhook kuralı: helper'la doğrulanan rota ARTIK işaretlenmez (crm deseni)", async () => {
    const ctx = makeCtx({
      "lib/webhook-guvenlik.ts": `export function isWebhookAuthorized(req: Request): boolean {\n  const secret = process.env.WHATSAPP_WEBHOOK_SECRET?.trim();\n  if (!secret) return false;\n  const bearer = req.headers.get("authorization");\n  return bearer === \`Bearer \${secret}\`;\n}`,
      "app/api/whatsapp/webhook/route.ts": `import { isWebhookAuthorized } from "@/lib/webhook-guvenlik";\nimport { getAdminClient } from "@/lib/supabase/admin";\nexport async function POST(req: NextRequest) {\n  if (!isWebhookAuthorized(req)) return new Response("unauthorized", { status: 401 });\n  const db = getAdminClient();\n  await db.from("messages").insert({ body: "x" });\n  return Response.json({ ok: true });\n}`,
    });
    const findings = await webhookSignature.run(ctx);
    expect(findings).toHaveLength(0);
  });

  it("gerçekten doğrulamasız webhook HÂLÂ yakalanır (recall koruması)", async () => {
    const ctx = makeCtx({
      "lib/webhook-guvenlik.ts": `export function isWebhookAuthorized(req: Request): boolean {\n  const secret = process.env.WHATSAPP_WEBHOOK_SECRET?.trim();\n  if (!secret) return false;\n  return true;\n}`,
      "app/api/whatsapp/webhook/route.ts": `import { getAdminClient } from "@/lib/supabase/admin";\nexport async function POST(req: NextRequest) {\n  const db = getAdminClient();\n  await db.from("messages").insert({ body: "x" });\n  return Response.json({ ok: true });\n}`,
    });
    const findings = await webhookSignature.run(ctx);
    // kapıyı hiç çağırmıyor → bulgu beklenir
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});
