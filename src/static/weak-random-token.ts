import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import { bytesKeyspaceBits, strengthFromBits } from "../core/shannon.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A07 — tokens generated from predictable randomness.
 *
 * Math.random() is xorshift128+ (v8), NOT a CSPRNG: its internal state can be
 * reconstructed from a handful of outputs. Date.now() carries ~1000 possible
 * values per second — an attacker who roughly knows WHEN a token was issued
 * only has to enumerate a moment. Neither is a randomness source for anything
 * authentication-shaped.
 *
 * The Shannon head's job here is the ARITHMETIC of the claim, not just the
 * pattern: a CSPRNG is also flagged when the DRAW is too small. randomBytes(8)
 * is a "real" CSPRNG whose keyspace is 64 bits — measured, that is a weak
 * token, whatever the source. Strength bands live in core/shannon.ts
 * (< 64 weak, < 112 marginal, 112+ strong).
 *
 * Detection and reporting only.
 */

const CODE_FILE = /\.(js|jsx|ts|tsx|mjs|cjs|mts|cts|vue|svelte|py|rb|php|go|java|cs)$/i;

/**
 * Names that make a value security-carrying (auth surface). Deliberately
 * NARROW: every extra name here is a false-positive factory. "id" was tried
 * and removed — it matched "unpaid", "paid", every UI list key
 * (`{ id: Date.now() + Math.random() }` in seed data) and produced ~40
 * findings that were all noise.
 */
const AUTH_NAME =
  /(token|secret|password|passwd|pwd|api[_-]?key|apikey|otp|onetime|csrf|xsrf|verification|verify|reset|invite|activation|magic|(auth|access|verify|reset)[_-]?code|coupon|voucher)/i;

/**
 * "nonce" TEK başına değil: gerçek vaka (korpus, 2 sahte HIGH) — Türkçe tarih
 * değişkeni `ondortGunOnce` (on dört gün önce) içindeki "nOnce", /nonce/i
 * desenini tuttu. Nonce adı ya sözcük başıdır ya _/-/rakamdan sonra gelir ya
 * da camelCase'de BÜYÜK harfle başlar (csrfNonce). "xOnce" bunların hiçbiri
 * değildir.
 */
const NONCE_NAME = /(^|[^a-zA-Z])nonce|[a-z]Nonce/;

/** auth surface kararının tek yeri. */
const authSurface = (name: string): boolean =>
  AUTH_NAME.test(name) || NONCE_NAME.test(name);

/**
 * NEGATIVE signal — a TIMESTAMP field name, not a randomness consumer.
 * `session.updatedAt = Date.now()`, `inviteExpiresAt`, `resetTime` are date
 * arithmetic; firing on them produced the bulk of the corpus noise. The
 * strong-name requirement below plus this filter is what keeps the rule quiet
 * on normal code.
 */
const TIMESTAMP_NAME =
  /(created|updated|deleted|modified|expires|expiry|started|ended|last[_-]?seen|since|until|duration|elapsed|delay|timestamp|(At|Time|Since|Stamp|Date)$)/i;

/** Weak randomness sources. */
// performance.now() BILINÇLI olarak yok: monoton süreç saattir, süre ölçer —
// rastgelelik kaynağı değildir. Gerçek vaka (korpus, 3 sahte bulgu):
// `recordingStartedAtRef.current = performance.now()`.
const WEAK_JS = /(Math\.random\s*\(\s*\)|Date\.now\s*\(\s*\)|new\s+Date\s*\(\s*\)\s*\.\s*(getTime|valueOf)\s*\(\s*\))/;

/** Python's Mersenne Twister — same verdict, different costume. */
const WEAK_PY = /\brandom\.(random|randint|randrange|choice|choices|getrandbits|uniform)\s*\(/;

/**
 * Small CSPRNG draws: the source is fine, the BUDGET is not.
 * Captures the byte count so the keyspace can be measured, not guessed.
 */
const SMALL_DRAW =
  /(?:randomBytes\s*\(\s*(\d{1,3})\s*\)|getRandomValues\s*\(\s*new\s+Uint8Array\s*\(\s*(\d{1,3})\s*\)\s*\)|os\.urandom\s*\(\s*(\d{1,3})\s*\))/;

/** Names that are session/auth surface even when the variable is not obvious. */
const TOKEN_ISH = /(token|secret|session|csrf|otp|nonce|password|apikey|api_key|salt|verification|reset|invite)/i;

interface Hit {
  line: number;
  text: string;
  severity: "high" | "medium";
  what: string;
  keyspace?: number;
  fix: string;
}

export const weakRandomToken: StaticRule = {
  id: "a07-weak-random-token",
  title: "Token or identifier generated from predictable randomness",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "high",
  cwe: "CWE-338",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (!CODE_FILE.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        // The engine blanks comments for us; the remaining line is code.
        const line = raw;
        const hits: Hit[] = [];

        // 1) Weak source assigned to a security-carrying name.
        if (WEAK_JS.test(line)) {
          const nameMatch = /([\w.$-]+)\s*[:=]/.exec(line);
          const name = nameMatch?.[1] ?? "";
          // Date.now() ikiye ayrılır: zaman damgası ataması (createdAt,
          // updatedAt, expiresAt) SORUN DEĞİLDIR; yalnızca güvenlik-değeri
          // üretimi sorunludur. Zaman-damgası isimleri sessizliğe gider.
          const timestampish = TIMESTAMP_NAME.test(name);
          if (authSurface(name) && !timestampish) {
            hits.push({
              line: i + 1,
              text: raw,
              severity: "high",
              what: `A security-carrying value ("${name}") is derived from Math.random()/Date.now(), which are predictable.`,
              fix: "Use crypto.randomUUID() or crypto.getRandomValues()/randomBytes(32) instead of Math.random()/Date.now().",
            });
          }
        }

        // 2) Python's Mersenne Twister on the same surface.
        if (WEAK_PY.test(line)) {
          const nameMatch = /^\s*(\w+)\s*[:=]/.exec(line);
          const name = nameMatch?.[1] ?? "";
          if (authSurface(name) && !TIMESTAMP_NAME.test(name)) {
            hits.push({
              line: i + 1,
              text: raw,
              severity: "high",
              what: `A value ("${name}") is derived from Python's random module (Mersenne Twister — predictable, not a CSPRNG).`,
              fix: "Use the secrets module (secrets.token_hex/secret.token_urlsafe) instead of the random module.",
            });
          }
        }

        // 3) A real CSPRNG asked for too few bytes — the Shannon head measures
        //    the keyspace and reports the NUMBER, not a hunch.
        const draw = SMALL_DRAW.exec(line);
        if (draw && TOKEN_ISH.test(line)) {
          const bytes = Number(draw[1] ?? draw[2] ?? draw[3]);
          if (Number.isFinite(bytes) && bytes > 0) {
            const bits = bytesKeyspaceBits(bytes);
            if (strengthFromBits(bits) !== "strong") {
              hits.push({
                line: i + 1,
                text: raw,
                severity: strengthFromBits(bits) === "weak" ? "high" : "medium",
                what: `A CSPRNG draw of ${bytes} byte(s) feeds a token-like value — measured keyspace ${bits} bits (${strengthFromBits(bits)}).`,
                fix: "Draw at least 16 bytes (128 bits) for tokens: randomBytes(32) / crypto.getRandomValues(new Uint8Array(32)).",
              });
            }
          }
        }

        for (const h of hits) {
          findings.push({
            ruleId: this.id,
            title: this.title,
            owasp: this.owasp,
            severity: h.severity,
            description: `${h.what} Predictable identifiers make session fixation, ID enumeration and brute-force feasible.`,
            evidence: [fileEvidence(file, h.line, h.text)],
            remediation: h.fix,
          });
        }
      }
    }
    return findings;
  },
};
