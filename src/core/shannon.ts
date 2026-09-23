/**
 * SHANNON CORE — the measurement brain ("Shannon kafasi").
 *
 * Every rule that asks "how random is this string, really?" measures through
 * here, so there is one maths instead of a private 6-line copy per rule.
 *
 * Three measures, NOT interchangeable:
 *
 *  1. `shannonEntropy(s)`    — H in bits/char. How surprised are we by the next
 *                              character, given the observed frequencies.
 *  2. `normalizedEntropy(s)` — H divided by the CHARSET CEILING of the class
 *                              the string was drawn from. "Random FOR ITS
 *                              ALPHABET." A 40-char hex string can never exceed
 *                              4 bits/char: 3.9 there is excellent, in base64
 *                              it is mediocre. Raw H alone misleads, which is
 *                              exactly how "coindesk-cd03c41e…" got flagged as
 *                              an OpenAI key in a real scan (see
 *                              static/hardcoded-secrets.ts).
 *  3. `keyspaceBits(s)`      — log2(charset^length): the brute-force budget of
 *                              the WHOLE string. A token's security claim is a
 *                              keyspace claim, so thresholds are absolute:
 *                              below 64 bits is online-guessable territory,
 *                              112+ is the conventional "strong" line.
 *
 * Plus two structure checks entropy cannot see:
 *  - `maxRun(s)`      — "aaaaaaaaaaaa" has length but carries no information.
 *  - `dgaLikeness(s)` — algorithmically generated hostnames have a vowel and
 *                       entropy signature human names rarely produce.
 *
 * Measurement and reporting only: this module never mutates anything, it
 * measures. Stdlib-free by design (no imports), like the rest of core.
 */

/** Charset classes a string can be recognised as, with their ceilings. */
export type CharsetClass = "hex" | "base32" | "base64" | "alnum" | "printable" | "text";

/** Maximum bits/char each class could carry (log2 of its alphabet size). */
export const CLASS_CEILING: Record<CharsetClass, number> = {
  hex: 4, // 16 symbols
  base32: 5, // 32 symbols
  base64: 6, // 64 symbols
  alnum: Math.log2(62),
  printable: Math.log2(94),
  // Arbitrary unicode: the ceiling is the observed alphabet itself, so the
  // normalized value is 1 by construction and carries no signal.
  text: Number.NaN,
};

export interface EntropyProfile {
  /** Length in characters. */
  length: number;
  /** Number of distinct characters. */
  distinct: number;
  /** Shannon entropy H, bits per character. */
  entropyBits: number;
  /** Inferred charset class. */
  klass: CharsetClass;
  /** Ceiling of that class, bits/char. */
  ceiling: number;
  /** H / ceiling, 0..1 (always 1 for "text"). */
  normalized: number;
  /** log2(ceiling_alphabet^length) — brute-force budget of the whole string. */
  keyspaceBits: number;
  /** Longest run of one repeated character. */
  maxRun: number;
}

const HEX_RE = /^[0-9a-fA-F]+$/;
const BASE32_RE = /^[A-Z2-7]+=*$/;
const BASE64_STD_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64_URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;
const ALNUM_RE = /^[A-Za-z0-9]+$/;
const PRINTABLE_RE = /^[\x21-\x7E]+$/;

/** Which alphabet does this string LOOK like it was drawn from? */
export function classify(s: string): CharsetClass {
  if (s.length === 0) return "text";
  if (HEX_RE.test(s)) return "hex";
  if (BASE32_RE.test(s)) return "base32";
  // alnum ÖNCE gelir: base64url alfabesi alnum'un üst kümesidir ve sembol
  // içermeyen bir dizgeye "base64" demek, keyspace'i 62^ yerine 64^'ten
  // okumaktır (12 karakterde 0.55 bit hata).
  if (ALNUM_RE.test(s)) return "alnum";
  // base64 tanısı ek şart ister: sembol VE 4'ün katı uzunluk (veya '=' dolgusu).
  // Aksi halde "sk_live_abc-DEF_123" gibi config değerleri base64 sanılır —
  // bunlar printable metindir, kodlanmış veri değil.
  const base64Shaped =
    (BASE64_STD_RE.test(s) || BASE64_URL_RE.test(s)) &&
    (s.length % 4 === 0 || s.endsWith("="));
  if (base64Shaped) return "base64";
  if (PRINTABLE_RE.test(s)) return "printable";
  return "text";
}

/**
 * Shannon entropy of a string, bits per character.
 * H = -Σ p·log2(p). Empty or single-symbol strings carry 0 bits.
 */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Longest run of one identical character ("aaaa" → 4). */
export function maxRun(s: string): number {
  let best = 0;
  let run = 0;
  let prev = "";
  for (const c of s) {
    run = c === prev ? run + 1 : 1;
    prev = c;
    if (run > best) best = run;
  }
  return best;
}

/**
 * Brute-force budget of the whole string: log2(ceiling^length).
 * Measured against the INFERRED alphabet, not the observed one — "deadbeef"
 * was probably drawn from hex (16 symbols), so its budget is 8·4 = 32 bits,
 * no matter that only 5 distinct letters appear.
 */
export function keyspaceBits(s: string): number {
  if (s.length === 0) return 0;
  const klass = classify(s);
  const ceiling = CLASS_CEILING[klass];
  if (klass === "text") {
    // Lower bound: the observed alphabet is all we can honestly claim.
    const distinct = new Set(s).size;
    return s.length * Math.log2(Math.max(distinct, 2));
  }
  return s.length * ceiling;
}

/** Keyspace of an n-byte CSPRNG draw, for rules that see a byte count. */
export function bytesKeyspaceBits(bytes: number): number {
  return bytes * 8;
}

/**
 * Absolute strength bands for a keyspace (bits).
 *  < 64  → weak: online-guessable, brute-forceable budgets.
 *  < 112 → marginal: resists casual attack, below the conventional strong line.
 *  ≥ 112 → strong: 112 is the smallest widely-accepted "still strong" figure
 *          (3DES/AES-112 floor); 128 is what session tokens should target.
 */
export type TokenStrength = "weak" | "marginal" | "strong";
export const WEAK_KEYSPACE_BITS = 64;
export const STRONG_KEYSPACE_BITS = 112;

export function strengthFromBits(bits: number): TokenStrength {
  if (bits < WEAK_KEYSPACE_BITS) return "weak";
  if (bits < STRONG_KEYSPACE_BITS) return "marginal";
  return "strong";
}

/** Full measurement in one pass — what rules should log into descriptions. */
export function profile(s: string): EntropyProfile {
  const klass = classify(s);
  const ceiling = CLASS_CEILING[klass];
  const h = shannonEntropy(s);
  return {
    length: s.length,
    distinct: s.length === 0 ? 0 : new Set(s).size,
    entropyBits: h,
    klass,
    ceiling,
    normalized: klass === "text" ? 1 : h / ceiling,
    keyspaceBits: keyspaceBits(s),
    maxRun: maxRun(s),
  };
}

/**
 * Normalized entropy alone: 0..1 against the class ceiling.
 * Use this when you want "is this random FOR ITS ALPHABET" in one number.
 */
export function normalizedEntropy(s: string): number {
  return profile(s).normalized;
}

/**
 * DGA-likeness of a hostname, 0..1 — a TRIAGE signal, not a verdict.
 *
 * Randomly generated subdomains/hosts (malware C2, throwaway phishing hosts)
 * are near-uniform over their alphabet: entropy close to the 26-letter
 * ceiling, vowel ratio far from natural language (~0.38 in English), and long
 * consonant runs. A human word fails at least two of these; a DGA usually
 * passes all. Deliberately conservative: below 0.65 means "nothing to say".
 */
const VOWELS = new Set([...("aeiou" + "ıioöuü")]);
const COMMON_LABELS = new Set([
  "www", "app", "api", "mail", "smtp", "ftp", "cdn", "static", "assets",
  "auth", "login", "admin", "panel", "test", "staging", "dev", "beta",
  "shop", "blog", "news", "support", "help", "docs", "status", "img",
  "images", "media", "video", "download", "update", "ns1", "ns2",
]);
const TLDS = new Set([
  "com", "org", "net", "edu", "gov", "dev", "app", "io", "co", "me", "ai",
  "tr", "de", "uk", "fr", "nl", "eu", "xyz", "site", "online", "store",
  "tech", "cloud", "top", "info", "biz", "net.tr", "com.tr", "org.tr",
]);

export function dgaLikeness(host: string): number {
  const clean = host.toLowerCase().trim().replace(/\/.*$/, "").replace(/:\d+$/, "");
  const labels = clean.split(".").filter(Boolean);
  const candidates = labels.filter(
    (l) => !TLDS.has(l) && !COMMON_LABELS.has(l) && l.length >= 6,
  );
  // Judge the most distinctive label we were left with.
  const label = candidates.sort((a, b) => b.length - a.length)[0];
  if (!label) return 0;

  const letters = label.replace(/[^a-z]/g, "");
  if (letters.length < 6) return 0;

  // 1) Entropy close to the lowercase-alphabet ceiling. Only meaningful with
  //    enough sample: 8 distinct letters can never exceed log2(8) = 3 bits/char,
  //    so a short "random-looking" label would read as LOW entropy and a short
  //    human word as high. Below 12 letters this signal is silent.
  let score = 0;
  if (letters.length >= 12) {
    const distinct = new Set(letters).size;
    const ceiling = Math.min(Math.log2(26), Math.log2(distinct));
    const norm = shannonEntropy(letters) / ceiling;
    if (norm >= 0.92) score += 0.35;
    else if (norm >= 0.85) score += 0.2;
  }

  // 2) Vowel ratio far from natural language.
  const vowels = [...letters].filter((c) => VOWELS.has(c)).length / letters.length;
  const drift = Math.abs(vowels - 0.38);
  if (drift >= 0.28) score += 0.3;
  else if (drift >= 0.2) score += 0.15;

  // 3) Unpronounceable consonant pile-ups.
  let run = 0;
  let longestConsonants = 0;
  for (const c of letters) {
    if (VOWELS.has(c)) run = 0;
    else {
      run += 1;
      if (run > longestConsonants) longestConsonants = run;
    }
  }
  if (longestConsonants >= 6) score += 0.35;
  else if (longestConsonants >= 5) score += 0.2;

  // 4) Heavy digit padding inside the name ("kx7wq2nd9pz").
  const digits = label.length - letters.length;
  if (digits / label.length > 0.2) score += 0.1;

  // 0.3 + 0.35 = 0.6499999999999999 in IEEE754 — round to a stable 2 decimals
  // so the threshold comparison is not a coin flip on representation error.
  return Math.min(1, Math.round(score * 100) / 100);
}

/** Convenience threshold matching the triage comment above. */
export const DGA_THRESHOLD = 0.65;
