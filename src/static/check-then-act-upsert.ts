import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — a check-then-act (TOCTOU) race: SELECT-then-conditional INSERT/UPDATE.
 *
 * A common anti-pattern: SELECT to ask "does the record exist?", then UPDATE if
 * it does and INSERT if it does not. The two steps are NOT ATOMIC: two
 * concurrent callers can both see "missing" and both attempt an INSERT. If the
 * key is UNIQUE the second INSERT throws a constraint violation (the request
 *
 * Real case: several save/upsert helpers all followed SELECT-then-UPDATE/INSERT.
 * The fix: an `ON CONFLICT` upsert, or wrapping the INSERT in
 * `try/except IntegrityError` and falling back to an update.
 *
 * PRECISION: the rule now requires the SAME FUNCTION — when SELECT, INSERT and
 * UPDATE live in different functions there is no race (file-level matching gave
 * 0% precision). Safe signals: ON CONFLICT,
 * INSERT OR REPLACE/IGNORE, ya da INSERT'i saran try + except IntegrityError.
 */

// NOT (2026-09-22): tools/scripts dışlaması DENENDİ ve geri alındı — canary
// disiplini bunu yakaladı: yarış koşulu tek seferlik betikte de mümkündür
// (cron çift çalıştırma, paralel import). Kural geniş kalır; bu kümenin
// gerçek düzeltmesi "kurulum betiği bağlamını tanıma" ayrı bir çalışmadır.
const isSourceLike = (f: string) =>
  /\.(py|js|ts|mjs|cjs|rb|go)$/.test(f) && !/(test|spec|conftest|fixtures?)/.test(f);

const girinti = (t: string): number => (t.match(/^[ \t]*/)?.[0].length ?? 0);
const isPyFuncHead = (t: string) => /^\s*(async\s+def|def)\s+\w+/.test(t);
const isPyBoundary = (t: string) => /^\s*(async\s+def|def|class)\s+\w+/.test(t);
// JS/TS function heads: declarations, const arrows, method shorthand. Needed
// because the ORM branch is JS-shaped and the whole-file "function" fallback
// broke same-function precision.
const isJsFuncHead = (t: string) =>
  /^\s*(export\s+)?(default\s+)?(async\s+)?function\s+[\w$]+/.test(t) ||
  /^\s*(export\s+)?(const|let|var)\s+[\w$]+\s*=\s*(async\s*)?(\(|function\b)/.test(t) ||
  /^\s*(async\s+)?[#$\w]+\s*\([^)]*\)\s*\{/.test(t);
const isFuncHead = (t: string) => isPyFuncHead(t) || isJsFuncHead(t);
const isBoundary = (t: string) => isPyBoundary(t) || isJsFuncHead(t);

/** The [start, end) line range (0-indexed) of the function enclosing the INSERT line. */
function enclosingRange(lines: string[], idx: number): [number, number] {
  // Start: walk up to a function head with less indentation.
  const insIndent = girinti(lines[idx] ?? "");
  let bas = 0;
  let headIndent = 0;
  for (let i = idx; i >= 0; i--) {
    const l = lines[i] ?? "";
    if (l.trim() === "") continue;
    if (isFuncHead(l) && girinti(l) < insIndent) {
      bas = i;
      headIndent = girinti(l);
      break;
    }
  }
  // End: after the function head, a boundary at the same or less indentation.
  let son = lines.length;
  for (let i = bas + 1; i < lines.length; i++) {
    const l = lines[i] ?? "";
    if (l.trim() === "") continue;
    if (isBoundary(l) && girinti(l) <= headIndent) {
      son = i;
      break;
    }
  }
  return [bas, son];
}

export const checkThenActUpsert: StaticRule = {
  id: "a04-check-then-act-upsert",
  title: "Check-then-act race: SELECT-then-conditional INSERT/UPDATE (not atomic)",
  owasp: "A04:2021-Insecure Design",
  severity: "low",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const insHits = ctx.grep(/INSERT\s+(OR\s+\w+\s+)?INTO\s+["'`]?\w+/i);
    const gorulen = new Set<string>();

    for (const m of insHits) {
      if (!isSourceLike(m.file)) continue;
      const content = ctx.read(m.file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      const line = lines[m.line - 1] ?? "";
      const tm = line.match(/INSERT\s+(?:OR\s+(\w+)\s+)?INTO\s+["'`]?(\w+)["'`]?/i);
      if (!tm) continue;
      const orMode = tm[1];         // REPLACE / IGNORE varsa atomik
      const tablo = tm[2];
      if (orMode && /^(replace|ignore)$/i.test(orMode)) continue; // atomik

      const anahtar = `${m.file}::${tablo}::${m.line}`;
      if (gorulen.has(anahtar)) continue;

      // THE ENCLOSING FUNCTION: SELECT, UPDATE and safe signals are all looked for in this range.
      const [bas, son] = enclosingRange(lines, m.line - 1);
      const body = lines.slice(bas, son).join("\n");

      // Safe signal 1: ON CONFLICT (continuing the INSERT statement, within the function)
      if (/ON\s+CONFLICT|ON\s+DUPLICATE\s+KEY/i.test(body)) continue;
      // Safe signal 2: a try wrapping the INSERT with except IntegrityError (meaning
      // it falls back to an update when it loses the race).
      if (/except[\s\w.(]*IntegrityError/i.test(body)) continue;

      // Is there an existence-check SELECT plus an UPDATE on this table IN THE SAME FUNCTION?
      const hasSelect = new RegExp(
        `SELECT\\s+[\\s\\S]{0,200}?FROM\\s+["'\`]?${tablo}\\b[\\s\\S]{0,160}?\\bWHERE\\b`, "i")
        .test(body);
      const hasUpdate = new RegExp(`UPDATE\\s+["'\`]?${tablo}\\b[\\s\\S]{0,80}?\\bSET\\b`, "i")
        .test(body);
      if (!hasSelect || !hasUpdate) continue;

      gorulen.add(anahtar);
      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "low",
        description:
          `${m.file}:${m.line} — the same function does a SELECT-then-conditional ` +
          `INSERT/UPDATE against '${tablo}', and it is not atomic ` +
          `(ne ON CONFLICT ne INSERT OR REPLACE ne de except IntegrityError). ` +
          `Two concurrent callers can both see "missing" and both INSERT; if the key ` +
          `is UNIQUE the second one throws a constraint violation, otherwise you get duplicates.`,
        evidence: [fileEvidence(m.file, m.line, `INSERT INTO ${tablo}`)],
        remediation:
          "Tek atomik ifade: `INSERT ... ON CONFLICT(anahtar) DO UPDATE SET ...` " +
          "(SQLite/Postgres) / `ON DUPLICATE KEY UPDATE` (MySQL). Alternatif: " +
          "Wrap the INSERT in `try/except IntegrityError` and fall back to an update.",
      });
    }

    // ORM BRANCH (2026-09-24): findUnique/findFirst ("does it exist?") followed
    // by create/update on the SAME accessor in the SAME function is the same
    // TOCTOU race in ORM clothes — no `INSERT INTO` text for the pass above to
    // see (recall suite: lib/save-order.ts). Safe: upsert() and $transaction
    // are atomic alternatives.
    const ormHits = ctx.grep(/\.\s*(findUnique|findFirst)\s*\(/);
    const islemGorulen = new Set<string>();
    for (const m of ormHits) {
      if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(m.file)) continue;
      if (/(test|spec|conftest|fixtures?)/.test(m.file)) continue;
      const content = ctx.read(m.file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      const line = lines[m.line - 1] ?? "";
      const am = /\.(\w+)\s*\.\s*(findUnique|findFirst)\s*\(/.exec(line);
      if (!am) continue;
      const erisici = am[1];
      const anahtar = `${m.file}::${erisici}::${m.line}`;
      if (islemGorulen.has(anahtar)) continue;

      const [bas, son] = enclosingRange(lines, m.line - 1);
      const body = lines.slice(bas, son).join("\n");

      // atomic alternatives win
      if (new RegExp(`\\.${erisici}\\s*\\.\\s*upsert\\s*\\(`).test(body)) continue;
      if (/\$\s*transaction\s*\(/.test(body)) continue;

      // the write on the SAME accessor, in the SAME function, plus a branch
      const yazma = new RegExp(
        `\\.${erisici}\\s*\\.\\s*(create|update|createMany|updateMany|delete|deleteMany)\\s*\\(`,
      );
      const yazmaSatiri = lines.findIndex(
        (l, i) => i >= bas && i < son && yazma.test(l),
      );
      if (yazmaSatiri === -1) continue;
      if (!/\bif\s*\(|\?\s*[^:?]+\s*:/.test(body)) continue;

      islemGorulen.add(anahtar);
      findings.push({
        ruleId: this.id,
        title: "Check-then-act race in ORM access (findUnique → create/update, not atomic)",
        owasp: this.owasp,
        severity: "low",
        description:
          `${m.file}:${m.line} — the same function asks "${erisici}.findUnique/findFirst" ` +
          `and then writes via "${erisici}.${lines[yazmaSatiri].match(yazma)?.[1]}()" (line ${yazmaSatiri + 1}). ` +
          `The check and the write are not atomic: two concurrent callers can both see "missing" and both create, ` +
          `producing duplicates or a unique-constraint failure.`,
        evidence: [fileEvidence(m.file, yazmaSatiri + 1, lines[yazmaSatiri].trim().slice(0, 100))],
        remediation:
          "Use the atomic alternative: prisma's upsert() (create or update in one call) or wrap " +
          "check+write in a transaction with a unique constraint as the final guard.",
      });
    }
    return findings;
  },
};
