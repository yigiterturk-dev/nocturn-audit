import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { webhookIdempotencyTtl } from "../src/static/webhook-idempotency-ttl.js";

const run = (files: Record<string, string>) =>
  webhookIdempotencyTtl.run(makeCtx(files)) as Array<{ severity: string }>;

const BAD = `
import { rateLimited } from "@/lib/rate-limit";
import { changePlan } from "@/lib/data/mutations";
export async function POST(req: Request) {
  const event = await provider.parseWebhook(await req.text(), req.headers.get("sig"));
  const lockKey = \`webhook:evt:\${event.eventId}\`;
  const seen = await rateLimited(lockKey, {
    windowMs: 24 * 60 * 60 * 1000,
    max: 1,
  });
  if (seen) return Response.json({ duplicate: true });
  await changePlan(event.businessId, event.planId, true);
  return Response.json({ ok: true });
}`;

const CLEAN_UNIQUE_ROW = `
import { changePlan } from "@/lib/data/mutations";
export async function POST(req: Request) {
  const event = await provider.parseWebhook(await req.text(), req.headers.get("sig"));
  const inserted = await db.insert(processedEvents).values({ eventId: event.eventId }).onConflictDoNothing().returning();
  if (inserted.length === 0) return Response.json({ duplicate: true });
  await changePlan(event.businessId, event.planId, true);
  return Response.json({ ok: true });
}`;

// Rate-limits the CALLER by IP — not an idempotency key. Different concern, must stay quiet.
const CLEAN_IP_RATELIMIT = `
import { rateLimited, clientIp } from "@/lib/rate-limit";
import { changePlan } from "@/lib/data/mutations";
export async function POST(req: Request) {
  if (await rateLimited(\`webhook-ip:\${await clientIp()}\`, { windowMs: 60_000, max: 100 })) return new Response(null, { status: 429 });
  const event = await provider.parseWebhook(await req.text(), req.headers.get("sig"));
  const inserted = await db.insert(processedEvents).values({ eventId: event.eventId }).onConflictDoNothing().returning();
  if (inserted.length === 0) return Response.json({ duplicate: true });
  await changePlan(event.businessId, event.planId, true);
  return Response.json({ ok: true });
}`;

// The fixed bir rezervasyon SaaS shape: permanent claim helper first, TTL counter only as a
// fallback when the table is missing. Must be quiet.
const CLEAN_CLAIM_HELPER_WITH_TTL_FALLBACK = `
import { rateLimited } from "@/lib/rate-limit";
import { changePlan } from "@/lib/data";
import { claimWebhookEvent } from "@/lib/payments/webhook-events";
export async function POST(req: Request) {
  const event = await provider.parseWebhook(await req.text(), req.headers.get("sig"));
  const claim = await claimWebhookEvent(event.eventId);
  if (claim === "duplicate") return Response.json({ duplicate: true });
  const lockKey = \`webhook:evt:\${event.eventId}\`;
  if (claim === "unavailable") {
    const seen = await rateLimited(lockKey, { windowMs: 24 * 60 * 60 * 1000, max: 1 });
    if (seen) return Response.json({ duplicate: true });
  }
  await changePlan(event.businessId, event.planId, true);
  return Response.json({ ok: true });
}`;

describe("webhook-idempotency-ttl", () => {
  it("CLEAN: permanent claim helper with TTL fallback (comments stripped, code decides)", () => {
    expect(run({ "app/api/payments/webhook/route.ts": CLEAN_CLAIM_HELPER_WITH_TTL_FALLBACK }).length).toBe(0);
  });

  it("BAD: eventId lock in rate-limit counter before granting a paid plan", () => {
    expect(run({ "app/api/payments/webhook/route.ts": BAD }).length).toBe(1);
  });

  it("CLEAN: unique processed_events row", () => {
    expect(run({ "app/api/payments/webhook/route.ts": CLEAN_UNIQUE_ROW }).length).toBe(0);
  });

  it("CLEAN: IP rate limit on the endpoint is not an idempotency key", () => {
    expect(run({ "app/api/payments/webhook/route.ts": CLEAN_IP_RATELIMIT }).length).toBe(0);
  });

  it("CLEAN: same code outside a webhook route", () => {
    expect(run({ "lib/plans.ts": BAD }).length).toBe(0);
  });

  it("scaffold filled in", async () => {
    const mod = await import("../src/static/webhook-idempotency-ttl.js");
    expect((mod as Record<string, unknown>).SCAFFOLD_NOT_FILLED).toBeUndefined();
  });
});
