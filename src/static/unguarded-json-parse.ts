import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { lineNo, tryIcinde, ts } from "../core/ast.js";

/**
 * A04 — persisted or external JSON parsed without try/except →
 * one malformed row takes down the whole request or job.
 *
 * JSON held in a database column (price_history, raw_data, meta …) or in an
 * external response can rot over time: a half-written value, a hand edit, a
 * schema change, an empty string. If `json.loads(x)` is called on it without
 * try/except, ONE bad record raises JSONDecodeError and kills the whole page or
 * job — and it fails where the data is READ, not where it was WRITTEN, which
 * makes it hard to diagnose.
 *
 * Real case: an upsert routine read a price_history column with json.loads; one
 * corrupt history could have taken down not a single listing but the entire
 * upsert run. The fix: try/except JSONDecodeError → empty default, skip and log
 * the record.
 *
 * This rule flags a json.loads / JSON.parse call when there is no try/catch in
 * the same function body. Parses of constant literals (json.loads('{}')) and
 * already-guarded ones are filtered out.
 */

const PARSE = /\b(json\.loads|JSON\.parse|orjson\.loads|ujson\.loads|simplejson\.loads)\s*\(/;
const TRY_OPEN = /^\s*(try\s*:|try\s*\{)/;
const CATCH = /(except[\s\w.]*:|catch\s*\()/;
// A constant literal argument -> cannot be corrupt, noise.
const LITERAL_ARG = /\b(json\.loads|JSON\.parse|orjson\.loads|ujson\.loads|simplejson\.loads)\s*\(\s*['"`]/;

// NOT (2026-09-22): scripts/tools yüzeyini dışlamak DENDİ ve CANARY GERİ
// ÇEVİRDİ — canary'nin HOLE 9'u (setup.mjs: JSON.parse(readFileSync(config)))
// da scripts/ içindeydi; harici veriyi parse eden job'lar betik yüzeyinde de
// gerçek risktir. Yol bazlı daraltma YANLIŞTI; gerçek ayırt edici sinyal
// "kendi ürettiği artefaktı parse etmek" — o ayrı bir kural çalışması.
// Kural geniş kalır; korpus FP'leri belgelenmiş durumda (precision'a yansır).
const isSourceLike = (f: string) =>
  /\.(py|js|ts|mjs|cjs)$/.test(f) &&
  !/(test|spec|conftest|\.min\.)/.test(f) &&
  // GENERATED CODE IS NOT PROJECT CODE. The Prisma client parses its own
  // `runtimeDataModel` without a try; the project did not write it, cannot fix
  // it, and the next `prisma generate` overwrites it.
  !/(^|\/)(generated|\.prisma|node_modules)\//.test(f.replace(/\\/g, "/"));

export const unguardedJsonParse: StaticRule = {
  id: "a04-unguarded-json-parse",
  title: "Persisted or external JSON parsed without a guard (one bad record kills the job)",
  owasp: "A04:2021-Insecure Design",
  severity: "low",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const hits = ctx.grep(PARSE);
    if (hits.length === 0) return findings;

    const flaggedPerFile = new Map<string, number>();

    for (const m of hits) {
      if (!isSourceLike(m.file)) continue;
      const content = ctx.read(m.file);
      if (!content) continue;
      // KENDİ JSON ARAYÜZÜNÜ IMPLEMENTE EDEN dosya (gerçek vaka, 2026-09-23 —
      // flask src/flask/json/provider.py: `return json.loads(s, **kwargs)` —
      // sağlayıcı loads'un KENDİ implementasyonudur; aynayı kırık sanmak olur).
      if (/\.py$/.test(m.file) && /def\s+loads\s*\(/.test(content)) continue;
      const lines = content.split(/\r?\n/);
      const idx = m.line - 1;
      const line = lines[idx] ?? "";
      // .py reST docstring alanı (`:meth:` app.json.loads()`) — belge metnidir,
      // çağrı değil (gerçek vaka: flask json/__init__.py:81, 1 FP).
      if (/^\s*:(?:meth|func|class|mod)/.test(line)) continue;

      // A constant literal argument -> an incorruptible source, skip.
      if (LITERAL_ARG.test(line)) continue;

      // Is this parse call inside a try block?
      //
      // For Python, an INDENTATION-AWARE walk upwards: a large try block (such
      // as a retry loop where the parse sits dozens of lines below) must NOT
      // escape a fixed-window search. Walking up from the parse line we follow
      // only the headers that ENCLOSE it (lines with less indentation); if a
      // 'try:' encloses it, it is guarded, and if we hit a 'def/class' boundary
      // it is not.
      const girinti = (t: string) => (t.match(/^[ \t]*/)?.[0].length ?? 0);
      const parseIndent = girinti(line);
      const isJsFile = /\.(js|ts|mjs|cjs)$/.test(m.file);
      let korumali = false;

      if (isJsFile) {
        // JS/TS: THE TREE. A text walk was wrong in both directions — a 40-line
        // window missed large try blocks, and a line mistaken for `function`
        // (e.g. `const x = { fn: (a) =>`) cut the search short. On the tree the
        // question is one step: is this call inside a try, and is there a
        // function boundary in between (an outer try does not guard an inner async body).
        const ast = ctx.ast(m.file);
        if (ast) {
          let bulundu = false;
          const gez = (n: ts.Node): void => {
            if (bulundu) return;
            if (ts.isCallExpression(n) && lineNo(ast, n) === m.line) {
              const ifade = n.expression;
              const jsonParse =
                ts.isPropertyAccessExpression(ifade) &&
                ts.isIdentifier(ifade.expression) &&
                ifade.expression.text === "JSON" &&
                ifade.name.text === "parse";
              if (jsonParse) {
                bulundu = true;
                korumali = tryIcinde(n);
                return;
              }
            }
            ts.forEachChild(n, gez);
          };
          gez(ast.source);
          // If the call is not found on the tree (a match inside a comment or string) there is no finding.
          if (!bulundu) continue;
        } else {
          for (let i = idx; i >= Math.max(0, idx - 40); i--) {
            const l = lines[i] ?? "";
            if (i !== idx && /^\s*(function |const \w+\s*=\s*(async\s*)?\()/.test(l)) break;
            if (TRY_OPEN.test(l)) { korumali = true; break; }
          }
        }
      } else {
        // Python: follow only ENCLOSING headers (indentation < the smallest
        // enclosing indentation so far). If such a header is 'try:' it is guarded;
        // if it is 'def/class' that is the function boundary -> unguarded.
        // Intermediate headers such as for/if/with/while may enclose it: lower the indentation and continue.
        let saranIndent = parseIndent;
        for (let i = idx - 1; i >= 0; i--) {
          const l = lines[i] ?? "";
          if (l.trim() === "") continue;
          const ind = girinti(l);
          if (ind >= saranIndent) continue;   // a sibling or inner line, not enclosing
          if (TRY_OPEN.test(l)) { korumali = true; break; }
          if (/^\s*(def |class |async def )/.test(l)) break; // function boundary
          saranIndent = ind;                   // this header encloses it, move up
          if (ind === 0) break;                // reached module level
        }
      }
      if (korumali) continue;

      // At most one finding per file (bound the noise), but show the line.
      if (flaggedPerFile.has(m.file)) continue;
      flaggedPerFile.set(m.file, m.line);

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "low",
        description:
          `${m.file}:${m.line} JSON'u try/except olmadan parse ediyor. ` +
          `If the argument comes from a persisted column or an external response, a single ` +
          `malformed record takes down the whole request or job — and it fails where the data ` +
          `is READ, not where it was WRITTEN, which makes it hard to diagnose.`,
        evidence: [fileEvidence(m.file, m.line, line.trim().slice(0, 80))],
        remediation:
          "Wrap the parse in try/except (JSONDecodeError / SyntaxError); " +
          "fall back to a safe default (empty list or dict) on failure, skip the record " +
          "and log it. One bad row then cannot bring down the entire run.",
      });
    }
    return findings;
  },
};
