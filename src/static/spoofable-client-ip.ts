import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A07 — a security decision resting on a header the CLIENT can forge.
 *
 * When a security decision (rate limit, brute-force brake, IP allowlist)
 * derives the client IP from `X-Forwarded-For`, it is BYPASSABLE: the client
 * sends XFF, and most reverse proxies (nginx, Caddy) do not OVERWRITE it, they
 * APPEND. So XFF's first value is whatever the attacker wrote. For an attacker
 * sending a different XFF on every request, an IP-based brake counts EVERY
 * attempt as a new IP and never engages.
 *
 * Real case: a login brake read XFF's first value; 20 forged headers meant 20
 * different IPs, the brake fired zero times, and password attempts were
 * effectively unlimited. The fix: read the header the reverse proxy OVERWRITES
 * (X-Real-IP / {remote_host}).
 *
 * This rule flags places where XFF is read in a SECURITY context (rate limit,
 * throttle, attempt counter, allowlist). Reading XFF only for logging is
 * harmless, which is why we look for a security signal nearby.
 */

// Typical patterns that take XFF's first element (Python + JS):
//   request.headers.get('X-Forwarded-For').split(',')[0]
//   req.headers['x-forwarded-for'].split(',')[0]
//   headers.get("x-forwarded-for")
const XFF_READ =
  /x[-_]forwarded[-_]for/i;

// Is there a SECURITY DECISION signal in the same file? If XFF is read only for
// logging we do not report (noise). These keywords mean "we are restricting
// something by IP".
const SECURITY_CONTEXT =
  /(rate[-_]?limit|ratelimit|throttle|brute|deneme|attempt|_deneme|kilit|lockout|lock_out|allowlist|allow_list|whitelist|blocklist|ban|fren|limiter|too_many|429)/i;

// If it reads the header the reverse proxy overwrites (X-Real-IP / remote_addr /
// {remote_host}), this file is already doing it right.
// PLATFORM-OVERWRITTEN headers are safe too. Vercel writes
// `x-vercel-forwarded-for` itself and overwrites whatever the client sent;
// Cloudflare does the same for `cf-connecting-ip`. In one run, a project's login
// brake read `x-vercel-forwarded-for` first and fell back to XFF ONLY when that
// was absent — so on Vercel the brake uses the correct IP and XFF only matters
// in local development. That is not the same as the real hole (raw XFF behind
// nginx).
const SAFE_IP_SOURCE =
  /x[-_]real[-_]ip|remote_addr|remoteAddress|remote_host|trust.?proxy|x[-_]vercel[-_]forwarded[-_]for|cf[-_]connecting[-_]ip|true[-_]client[-_]ip|fly[-_]client[-_]ip/i;

// The idiom proving the line REALLY reads XFF (used to rule out a bare mention
// in a docstring or comment). Access forms: .headers / .get( / [ '..' ] / req. /
// environ / HTTP_X_FORWARDED / getHeader.
const XFF_ACCESS =
  /\.headers|\.get\(|\bget_header|getheader|\[\s*['"`]|req(uest)?\.|environ|HTTP_X_FORWARDED|forwarded_for['"`\]]/i;
// A SET directive or a comment line: not a READ of XFF. (nginx
// proxy_set_header / add_header, or a comment starting with # // *.)
const XFF_NOT_READ =
  /(proxy_)?set_header|add_header|fastcgi_param|^\s*(#|\/\/|\*|--)/i;
// Source code only: config files such as .conf/.nginx SET the header, they do
// NOT make a security decision.
const XFF_SOURCE = /\.(py|js|ts|mjs|cjs|rb|go|php|java|kt)$/i;

export const spoofableClientIp: StaticRule = {
  id: "a07-spoofable-client-ip",
  title: "Security decision relies on a spoofable X-Forwarded-For",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const matches = ctx.grep(XFF_READ);
    // Collect per file — but only REAL read lines:
    //   - a source file (not config),
    //   - the line contains an access idiom (to rule out a bare
    //     "X-Forwarded-For" mention in a docstring or comment),
    //   - the line is neither a SET directive nor a comment.
    const perFile = new Map<string, number>();
    for (const m of matches) {
      if (!XFF_SOURCE.test(m.file)) continue;
      const t = m.text ?? "";
      if (XFF_NOT_READ.test(t)) continue;
      if (!XFF_ACCESS.test(t)) continue;
      if (!perFile.has(m.file)) perFile.set(m.file, m.line);
    }

    for (const [file, line] of Array.from(perFile)) {
      const content = ctx.read(file);
      if (!content) continue;
      if (!SECURITY_CONTEXT.test(content)) continue; // skip when it is only logging

      // Does the same file also read a safe source (x-real-ip / req.ip / trust
      // okuyor mu?
      const safeToo = SAFE_IP_SOURCE.test(content);
      // If the platform header is read FIRST and XFF is only reached through
      // `||`/`??`, the fallback never runs in production (Vercel/Cloudflare set
      // their header on every request). The hole only materialises if the
      // project moves off that platform.
      const platformOnce =
        /(x[-_]vercel[-_]forwarded[-_]for|cf[-_]connecting[-_]ip|true[-_]client[-_]ip|fly[-_]client[-_]ip)[\s\S]{0,120}?(\|\||\?\?)[\s\S]{0,120}?x[-_]forwarded[-_]for/i.test(
          content,
        );
      // The FORGEABLE pattern: taking XFF's FIRST ([0]) value, which means
      // trusting what the client sent. The rightmost/last value
      // (parts.length-1, .at(-1), .pop()) is the proxy-set one and is safe.
      // ONLY plain `x-forwarded-for`'s [0] is forgeable. `x-vercel-forwarded-for`
      // and `x-real-ip` are proxy-trusted; their [0] is NOT a problem (the
      // platform sets them). Hence the `x-forwarded` condition (x- directly
      // before forwarded) — so vercel-forwarded does not match.
      const leftmostSpoof = /x[-_]forwarded[-_]for[\s\S]{0,80}?\[\s*0\s*\]/i.test(content);
      // THE CORRECT PATTERN: it prefers a safe source (x-real-ip) AND has no
      // spoofable leftmost [0] — the client cannot forge it, so do not report.
      // (The trustedIp fix in two projects is exactly this: x-real-ip first, XFF's LAST value.)
      if (safeToo && !leftmostSpoof) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: safeToo ? "low" : "high",
        description:
          `${file} reads X-Forwarded-For in a security decision (rate limit, attempt ` +
          `counter, allowlist). XFF is sent by the CLIENT, and reverse proxies often ` +
          `do not overwrite it — an attacker sends a different XFF on every request and ` +
          `BYPASSES the IP-based limit entirely (every attempt counts as a new IP).` +
          (platformOnce
            ? ` NOTE: the file reads the platform-set header first (x-vercel-forwarded-for / cf-connecting-ip) and only falls back to XFF when that is absent. On Vercel or Cloudflare that header is set on every request, so the fallback never runs IN PRODUCTION and the hole is not currently exploitable. Move the project off that platform (own server, Docker, nginx) and the limit becomes silently bypassable.`
            : safeToo
              ? ` The file also appears to read a trusted IP source; confirm the two are not mixed up.`
              : ``),
        evidence: [fileEvidence(file, line, "X-Forwarded-For")],
        remediation:
          "In security decisions, use the header your reverse proxy sets RELIABLY " +
          "okuyun (Caddy: X-Real-IP {remote_host}; nginx: $remote_addr / real_ip " +
          "module; Express: app.set('trust proxy', ...) with req.ip). Never TRUST " +
          "the first value of the client-controlled X-Forwarded-For.",
      });
    }
    return findings;
  },
};
