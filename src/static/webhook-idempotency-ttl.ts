import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — webhook "once only" lock lives in a TTL store.
 *
 * Origin (bir rezervasyon SaaS, 2026-09-08): the PayTR webhook deduplicated events by feeding
 * `eventId` into the rate-limit counter (`windowMs: 24h, max: 1`). The signature was
 * verified, so a forged event was impossible — but a CAPTURED valid notification
 * replayed after the window re-ran `changePlan(paid=true)` and granted another paid
 * period for free. Payment events have no natural expiry: "seen" must be permanent
 * (a unique row keyed by the provider's event id), not a counter that resets.
 */

const isWebhookRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/").toLowerCase();
  return (
    /(webhook|callback|ipn|notify|bildirim)/.test(f) &&
    (/(app\/.*\/route\.(ts|js))/.test(f) || /(pages\/api\/)/.test(f) || /(api\/.*\.(ts|js))/.test(f))
  );
};

// A dedup key built from the event/notification id …
const EVENT_KEY = /(eventId|event_id|merchant_oid|merchantOid|idempoten|evt:|webhook:)/i;
// … stored in something that EXPIRES.
const TTL_STORE =
  /(rateLimit(ed)?\s*\(|windowMs|ttl\s*[:=]|expire(At)?\s*\(|setex\s*\(|\bEX\b|\bPX\b|maxAge|cache\.set\(|lru|Map\(\))/i;
// The handler grants value on the strength of that lock.
const GRANTS =
  /(changePlan|activate\w*|markPaid|setPaid|paid\s*[:=]\s*true|grant\w*|extend\w*(Trial|Subscription|Paid)|paidUntil|entitle)/i;
// Permanent dedup = fine, whatever else the file does.
// NOTE: ctx.read() strips comments — a mention in a comment does not count, only code does.
const PERMANENT =
  /(onConflictDoNothing|claim\w*Event\w*\(|\bprocessedEvents\b|\bwebhookEvents\b|ON CONFLICT|processed_events|webhook_events|payment_events|INSERT\s+INTO\s+\w*(event|webhook)\w*|unique\w*\(|UNIQUE)/i;

export const webhookIdempotencyTtl: StaticRule = {
  id: "webhook-idempotency-ttl",
  title: "Webhook replay lock expires (TTL store used as idempotency key)",
  owasp: "A04:2021-Insecure Design",
  severity: "medium",
  kind: "static",
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!isWebhookRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      if (!GRANTS.test(content)) continue;
      if (PERMANENT.test(content)) continue;

      const lines = content.split("\n");
      const hit = lines.findIndex((l) => EVENT_KEY.test(l) && TTL_STORE.test(l));
      // Key and store may sit on adjacent lines (object literal spread over lines).
      const near =
        hit >= 0
          ? hit
          : lines.findIndex(
              (l, i) => EVENT_KEY.test(l) && TTL_STORE.test(lines.slice(i, i + 6).join("\n")),
            );
      if (near < 0) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "medium",
        confidence: "likely",
        description:
          "The webhook deduplicates events with a key kept in an expiring store (rate-limit counter, TTL cache, Map). Signature verification stops FORGED events, not REPLAYED ones: a captured valid notification re-sent after the window is processed again and grants the paid entitlement a second time.",
        evidence: [fileEvidence(file, near + 1, lines[near].trim())],
        remediation:
          "Record the provider's event id in a table with a UNIQUE constraint (processed_events) and insert ON CONFLICT DO NOTHING before granting; a rejected insert means 'already handled'. Payment events never expire, so the lock must not either.",
      });
    }
    return findings;
  },
};
