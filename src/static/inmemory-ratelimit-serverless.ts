import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — IN-MEMORY rate limiting on serverless → effectively useless.
 *
 * Vercel/Next serverless and edge functions are stateless and RESET on every
 * invocation (or at least per instance). If the rate-limit counter lives in a
 * module-level Map/Set/object/array, the counter does NOT persist: the moment
 * an attacker sees scale (a new instance) they meet a reset limit; in practice
 * there is NO brake. A durable store is required (Upstash/Redis/@vercel/kv/DB).
 *
 * Real case (recurring): "the in-memory rate limit resets on every instance"
 * was the common root cause across several audits. The fix: move to
 * Upstash/Redis and take the IP from req.ip.
 *
 * This rule flags a file when (a) the project is serverless (Next/Vercel),
 * (b) the file has rate-limit context, (c) the counter lives in a module-level
 * Map/Set/{}/[], and (d) NO durable store (redis/upstash/kv/db) is used.
 */

const RL_CONTEXT =
  /(rate[-_ ]?limit|ratelimit|throttle|too[-_ ]?many|\b429\b|_deneme\b|attempts?\b|brute|lockout|limiter)/i;
const INMEM_STORE =
  /^\s*(const|let|var)\s+\w+\s*(:[^=]+)?=\s*(new\s+(Map|Set)\s*(<[^>]*>)?\s*\(|\{\s*\}|\[\s*\])/;
// Durable store signals. CAREFUL: bare `Ratelimit` is NOT used — it collides
// with the common `rateLimit` function name. Only `new Ratelimit` / slidingWindow.
const PERSISTENT =
  /(upstash|@vercel\/kv|ioredis|\bredis\b|memcach|createClient|new\s+Ratelimit|slidingWindow|fixedWindow|prisma|drizzle|supabase|\bkv\.)/i;

const isJsTs = (f: string) =>
  /\.(js|ts|mjs|cjs|jsx|tsx)$/.test(f) && !/(test|spec|\.d\.ts$)/.test(f);

// Strip comments — the durable-store check must not trip over a word in a COMMENT.
// Real case: a file used `new Map()` while a comment said "should move to
// Upstash"; a raw text search read that as "a durable store exists" and MISSED
// the real in-memory store (a false negative).
function withoutComments(kod: string): string {
  return kod
    .replace(/\/\*[\s\S]*?\*\//g, " ")      // /* blok */
    .split(/\r?\n/)
    .map((l) => l.replace(/\/\/.*$/, "").replace(/^\s*\*.*$/, "")) // // lines + * jsdoc
    .join("\n");
}

export const inmemoryRatelimitServerless: StaticRule = {
  id: "a04-inmemory-ratelimit-serverless",
  title: "In-memory rate limiting on serverless (resets per instance, so it does nothing)",
  owasp: "A04:2021-Insecure Design",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // Is it serverless? Next/Vercel indicators.
    const serverless =
      ctx.exists("next.config.js") || ctx.exists("next.config.ts") ||
      ctx.exists("next.config.mjs") || ctx.exists("vercel.json") ||
      ctx.grep(/from\s+["']next\/server["']|export\s+const\s+runtime\s*=|@vercel\/|next\/server/i).length > 0;
    if (!serverless) return findings;

    // Files that have rate-limit context
    const rlHits = ctx.grep(RL_CONTEXT);
    const files = new Set(rlHits.map((h) => h.file).filter(isJsTs));

    for (const file of files) {
      const raw = ctx.read(file);
      if (!raw) continue;
      const content = withoutComments(raw);  // do not count 'upstash' etc. inside comments
      // If it uses a durable store (Upstash/Redis/KV/DB) there is no problem.
      if (PERSISTENT.test(content)) continue;

      // Is there an in-memory store at module level (no indentation)?
      const lines = content.split(/\r?\n/);
      let storeLine = -1;
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i] ?? "";
        // module level = not indented (not inside a function)
        if (/^\S/.test(l) && INMEM_STORE.test(l)) { storeLine = i + 1; break; }
      }
      if (storeLine < 0) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "medium",
        confidence: "likely",
        description:
          `${file} keeps its rate-limit counter in a module-level ` +
          `Map/Set/object/array (line ${storeLine}), but the project is ` +
          `serverless (Next/Vercel). That memory RESETS on every instance and every ` +
          `cold start, so the counter never persists and the limit does nothing. No ` +
          `durable store (Upstash/Redis/@vercel/kv) is used.`,
        evidence: [fileEvidence(file, storeLine, "module-level rate-limit store")],
        remediation:
          "Move the counter state into a durable, shared store: " +
          "@upstash/ratelimit with @vercel/kv, or Redis. Take the client IP from a " +
          "trusted source as well (trust proxy / req.ip).",
      });
    }
    return findings;
  },
};
