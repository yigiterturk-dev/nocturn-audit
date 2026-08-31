import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A09 — personal data written to LOGS.
 *
 * It looks harmless today: the log file sits on the server, it is gitignored,
 * nobody reads it. But logs get collected one day — Sentry, GlitchTip, Datadog,
 * CloudWatch — and on that day the personal data has gone to a THIRD PARTY.
 * Nobody goes back to ask "what was in those logs"; the integration is one
 * line, and the historical logs travel with it.
 *
 * In one project, error lines printed a property address and a company name;
 * three distinct street names were measured in the server logs. The address was
 * genuinely needed for debugging — the answer is not to drop it, but to MASK it.
 */

/** Log calls. */
/**
 * Log calls — PER LANGUAGE.
 *
 * This rule was born from a Python finding, yet it only read JS/TS — so it
 * could not see its own inspiration. An audit tool that catches a mistake in
 * one language but not another is saying "let us make the same mistake
 *
 * But the patterns have to be LANGUAGE-BOUND. Merged into a single regex,
 * Ruby's `p` print command matched JSX's `<p className=...>` tag and every
 * paragraph became a finding. One language's idiom is another's noise.
 * noise in another.
 */
const DIL_LOGLARI: Array<{ ext: RegExp; log: RegExp }> = [
  {
    ext: /\.(ts|tsx|js|jsx|mjs|cjs)$/,
    log: /\b(console\.(log|error|warn|info|debug)|logger?\.(log|error|warn|info|debug|trace)|process\.(stdout|stderr)\.write|captureException|captureMessage)\s*\(/,
  },
  {
    ext: /\.py$/,
    // `print` is DELIBERATELY absent: it is mostly terminal/CLI output (an
    // interactive admin tool and the like), not a durable log — in one project
    // it produced only false positives (a user-setup script echoing email and
    // password, a label-refresh script printing an address).
    // `logging.*` / `logger.*`, by contrast, is a clear durable log sink.
    log: /\b(logging\.(debug|info|warning|error|exception|critical)|log(ger)?\.(debug|info|warning|error|exception|critical))\s*\(/,
  },
  {
    ext: /\.go$/,
    log: /\b(fmt\.(Print|Printf|Println)|log\.(Print|Printf|Println|Fatal|Fatalf))\s*\(/,
  },
  {
    ext: /\.rs$/,
    log: /\b(println!|eprintln!|error!|warn!|info!|debug!)\s*\(/,
  },
  {
    ext: /\.rb$/,
    // `p` is not taken ON ITS OWN: it appears everywhere in JSX and as a maths
    // variable, and even filtered by language it stays risky inside Ruby.
    log: /\b(puts|pp|logger\.(debug|info|warn|error|fatal))\s+/,
  },
  {
    ext: /\.php$/,
    log: /\b(error_log|var_dump|print_r)\s*\(/,
  },
  {
    ext: /\.(java|kt)$/,
    log: /\b(System\.(out|err)\.print(ln)?|log(ger)?\.(debug|info|warn|error))\s*\(/,
  },
];

/** The log pattern that applies to this file. */
function logDeseni(file: string): RegExp | null {
  return DIL_LOGLARI.find((d) => d.ext.test(file))?.log ?? null;
}

/** Identifier fragments that suggest the value carries personal data. */
const KISISEL = new Set([
  "address", "adres", "adresi", "street", "sokak",
  "fullname", "firstname", "lastname", "surname", "soyad", "soyadi", "isim",
  "email", "eposta",
  "phone", "telefon", "mobile", "gsm",
  "ssn", "tckn", "passport", "birthdate", "dogumtarihi",
  "owner", "malik", "resident", "kiraci", "tenant", "applicant", "basvuran",
  "customer", "musteri", "cardnumber", "iban",
]);

/** Masking wrappers: the value inside is no longer personal data. */
const MASKE = /\b(mask\w*|maske\w*|redact\w*|anonym\w*|anonim\w*|sanitize\w*|scrub\w*|gizle\w*|hash\w*|obfuscat\w*|truncate\w*|kisalt\w*)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)/gi;

/** The companions that make a "name" fragment personal. */
const KISI = new Set([
  "first", "last", "full", "middle", "owner", "resident", "tenant", "applicant",
  "customer", "person", "contact", "malik", "sahip", "kiraci", "musteri", "user",
]);

/**
 * ID FIELDS are not personal data: logging an id or uuid is normal and useful.
 *
 * Both `resident_id` and `residentId` have to be recognised. The first version
 * knew only the underscored form, so `console.log({ residentId })` produced a
 * finding — in that state the rule would fire on every structured log line.
 */
const KIMLIK = /(^|_|[a-z0-9])(id|uuid|guid|key|ref|slug|code|no)$/i;

/**
 * AGGREGATE value names: counters, ratios, totals.
 *
 * A name like `has_surname_count` contains a personal-data word but its value
 * is a statistic. Those belong in logs; a statistic identifies nobody. Without
 * the distinction every summary line would be a finding.
 */
const TOPLU = new Set([
  "count", "total", "sum", "avg", "mean", "min", "max", "len", "length", "size",
  "num", "ratio", "rate", "pct", "percent", "yuzde", "oran",
  "adet", "sayi", "sayisi", "toplam", "ortalama",
  // Turkish predicate suffixes ("…olan", "…var", "…yok") describe a COUNT.
  "olan", "var", "yok", "eksik", "dolu", "bos",
]);

/** Drops string and template TEXT, keeps the code inside `${...}`. */
function sadeceKod(source: string): string {
  let out = "";
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    if (c === '"' || c === "'") {
      // A Python f-string (`f"...{x}..."`) behaves like a template literal: the
      // TEXT is dropped, the braces' CONTENTS kept — personal data passes there.
      const fString = /[fF]$/.test(out);
      let j = i + 1;
      let content = "";
      while (j < source.length) {
        if (source[j] === "\\") { j += 2; continue; }
        if (source[j] === c) { j += 1; break; }
        content += source[j];
        j += 1;
      }
      // Interpolation syntax differs per language but the idea is the same: text
      // is dropped, the CODE inside the braces is kept.
      //   Python f-string : f"... {x} ..."
      //   Ruby            : "... #{x} ..."
      //   Kotlin/Scala    : "... $x ..." (the simple form is not covered here)
      const rubyIc = [...content.matchAll(/#\{([^{}]+)\}/g)].map((m) => ` ${m[1]} `).join("");
      const fIc = fString
        ? [...content.matchAll(/\{([^{}]+)\}/g)].map((m) => ` ${m[1]} `).join("")
        : "";
      out += `${fIc}${rubyIc}` || " ";
      i = j;
      continue;
    }
    if (c === "`") {
      let j = i + 1;
      while (j < source.length && source[j] !== "`") {
        if (source[j] === "\\") { j += 2; continue; }
        if (source[j] === "$" && source[j + 1] === "{") {
          // Interpolation: the inside is CODE, kept.
          let derinlik = 1;
          let k = j + 2;
          const bas = k;
          while (k < source.length && derinlik > 0) {
            if (source[k] === "{") derinlik += 1;
            else if (source[k] === "}") derinlik -= 1;
            k += 1;
          }
          out += ` ${source.slice(bas, k - 1)} `;
          j = k;
          continue;
        }
        j += 1;
      }
      i = j + 1;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

/**
 * Splits an identifier into fragments and matches WHOLE fragments.
 *
 * The first version searched substrings, so `MAIL_STATE` (a postal STATE, not
 * personal data on its own) fired because it contained "mail". A state code
 * inside a percentage calculation is not personal data; whole-fragment matching
 * makes the distinction: `MAIL_STATE` → [mail, state] → no match, `ownerMail` →
 * [owner, mail] → "owner" matches.
 */
function parts(ad: string): string[] {
  return ad
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((x) => x.toLowerCase())
    .filter(Boolean);
}

/** Does this line pass personal data to a log call? */
function kisiselVeri(line: string, logRe: RegExp): string[] {
  const bulunan = new Set<string>();
  // Look for identifiers AFTER the log call.
  const parantez = line.search(logRe);
  if (parantez < 0) return [];
  // TEXT is dropped, only CODE remains.
  //
  // The log message itself is a label: in `console.log(\`postal address ${x}\`)`
  // the words "postal address" are not a variable but a human-facing caption —
  // and the value may be a percentage. The first version counted template text
  // as identifiers and fired on every line with a prose log message.
  //
  // The INSIDE of template interpolations is kept (`${...}`), because that is
  // where personal data passes.
  const argumanlar = sadeceKod(line.slice(parantez));

  // A MASKED value is not a finding.
  //
  // `maskAddress(h.address)` is the correct fix itself. If the rule cannot see
  // that, it stays red after the fix — and someone who keeps getting warned
  // about code they already fixed learns to ignore the rule. The worst state
  // for a rule is not being wrong, it is looking UNFIXABLE.
  const maskeli = new Set<string>();
  for (const m of argumanlar.matchAll(MASKE)) {
    // The wrapper's OWN NAME is skipped too: `maskAddress` → [mask, address],
    // `maskName` → [mask, name]. The rule was treating the solution's name as
    // the problem — naming a masking function sensibly would be impossible.
    maskeli.add(m[1]);
    for (const ic of m[2].matchAll(/\b([A-Za-z_][\w.]*)\b/g)) {
      maskeli.add((ic[1].split(".").pop() || ic[1]));
    }
  }

  for (const m of argumanlar.matchAll(/\b([A-Za-z_][\w.]*)\b/g)) {
    const tam = m[1];
    const son = tam.split(".").pop() || tam;
    if (KIMLIK.test(son)) continue;
    if (maskeli.has(son)) continue;
    if (parts(son).some((x) => TOPLU.has(x))) continue;
    const part = parts(son);
    if (part.some((x) => KISISEL.has(x))) { bulunan.add(son); continue; }
    // "name" is not a signal ON ITS OWN: `errorName`, `fileName`, `className`
    // are everywhere and none of them is personal data. It only means something
    // alongside a fragment that points at a person.
    if (part.includes("name") && part.some((x) => KISI.has(x))) bulunan.add(son);
  }
  return [...bulunan];
}

/** Do the logs go to a third party? */
function hasCollector(ctx: StaticContext): string | null {
  const paket = ctx.read("package.json") || "";
  const eslesme = paket.match(/"(@sentry\/[\w-]+|glitchtip|datadog[\w-]*|@datadog\/[\w-]+|winston-cloudwatch|pino-datadog|logtail|@logtail\/[\w-]+)"/);
  if (eslesme) return eslesme[1];
  if (ctx.grep(/SENTRY_DSN|GLITCHTIP|DATADOG_API_KEY/).length) return "a log collector (env)";
  return null;
}

export const piiInLogs: StaticRule = {
  id: "int-pii-in-logs",
  title: "Personal data written to logs",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  cwe: "CWE-532",
  run(ctx): Finding[] {
    const toplayici = hasCollector(ctx);
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      const logRe = logDeseni(file);
      if (!logRe) continue;
      const content = ctx.read(file);
      if (!content) continue;

      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i += 1) {
        const alanlar = kisiselVeri(lines[i], logRe);
        if (!alanlar.length) continue;

        findings.push({
          ruleId: "int-pii-in-logs",
          title: "Personal data written to logs",
          owasp: "A09:2021-Security Logging & Monitoring Failures",
          // If a collector exists, the data ALREADY goes to a third party.
          severity: toplayici ? "high" : "medium",
          confidence: "likely",
          cwe: "CWE-532",
          description:
            `\`${file}:${i + 1}\` passes personal data to a log call (${alanlar.slice(0, 4).join(", ")}). ` +
            (toplayici
              ? `This project has **${toplayici}** installed, so these lines already leave for a third party.`
              : "Today the logs may stay on the server; but the day log collection is added (Sentry, GlitchTip, " +
                "Datadog) personal data goes to a third party, and nobody ever goes back to check what the logs held."),
          evidence: [fileEvidence(file, i + 1, lines[i].trim().slice(0, 140))],
          remediation:
            "MASK the field rather than removing it — debugging usually needs it. Keeping the last part of " +
            "an address, the domain of an email, or the last four digits of a phone number solves most cases. " +
            "Or log the record id instead of its contents.",
        });
      }
    }
    return findings;
  },
};
