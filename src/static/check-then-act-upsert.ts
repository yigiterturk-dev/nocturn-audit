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

const isSourceLike = (f: string) =>
  /\.(py|js|ts|mjs|cjs|rb|go)$/.test(f) && !/(test|spec|conftest|fixtures?)/.test(f);

const girinti = (t: string): number => (t.match(/^[ \t]*/)?.[0].length ?? 0);
const isPyFuncHead = (t: string) => /^\s*(async\s+def|def)\s+\w+/.test(t);
const isPyBoundary = (t: string) => /^\s*(async\s+def|def|class)\s+\w+/.test(t);

/** The [start, end) line range (0-indexed) of the function enclosing the INSERT line. */
function enclosingRange(lines: string[], idx: number): [number, number] {
  const py = true; // Python is indentation based; this works reasonably for JS too
  // Start: walk up to a 'def' with less indentation.
  const insIndent = girinti(lines[idx] ?? "");
  let bas = 0;
  let headIndent = 0;
  for (let i = idx; i >= 0; i--) {
    const l = lines[i] ?? "";
    if (l.trim() === "") continue;
    if (isPyFuncHead(l) && girinti(l) < insIndent) {
      bas = i;
      headIndent = girinti(l);
      break;
    }
  }
  // End: after the function head, a boundary at the same or less indentation (def/class).
  let son = lines.length;
  for (let i = bas + 1; i < lines.length; i++) {
    const l = lines[i] ?? "";
    if (l.trim() === "") continue;
    if (isPyBoundary(l) && girinti(l) <= headIndent) {
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
    return findings;
  },
};
