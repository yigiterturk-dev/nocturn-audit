import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A03 — SQL COLUMN/TABLE NAME injection (an IDENTIFIER, not a value).
 *
 * Classic SQL-injection rules check whether the VALUE is parameterised
 * (`WHERE x = ?`). But IDENTIFIERS such as SET/ORDER BY or a table name cannot
 * be parameterised, and code usually builds them with string concatenation:
 *
 *   fields.append(f"{key} = ?")                      # key comes from the user
 *   f"UPDATE t SET {', '.join(fields)} WHERE id = ?"
 *   f"... ORDER BY {sirala}"
 *   f"SELECT * FROM {tablo}"
 *
 * If `key`, `sort` or `table` comes from a dict key or a query string, the WHERE
 * clause can be overridden even when the value is parameterised:
 *   {"is_active=0 WHERE 1=1 --": 1}  ->  SET is_active=0 WHERE 1=1 -- = ?
 *
 * Real case: an update_profile built its SET clause from data keys; the caller
 * passed a fixed dictionary so it was not exploitable, but the function itself
 * was vulnerable. The fix: constrain column names with an ALLOWLIST.
 */

const SQL_STMT = /\b(UPDATE|SELECT|INSERT|DELETE|ORDER\s+BY|GROUP\s+BY)\b/i;

// A VARIABLE interpolated into SQL via f-string / .format / %:
//   f"... SET {x} ..."   f"... FROM {x}"   f"... ORDER BY {x}"
//   "... {}".format(x)   "... %s" % x  (in an identifier context)
const FSTRING_INTERP = /f["'][^"']*\{[a-zA-Z_][\w.\[\]'"]*\}[^"']*["']/;

// Identifier context: is the interpolation in an IDENTIFIER position such as
// SET / FROM / ORDER BY / JOIN (rather than a value position like `= {x}`)?
const IDENT_POSITION =
  /\b(SET|FROM|JOIN|ORDER\s+BY|GROUP\s+BY|INTO)\b[^"']*\{[a-zA-Z_]|\bSET\b[^"']*\{|\{[^}]*\}\s*=\s*[?%]/i;

// Signals that the interpolated value may be a DICT KEY or external input.
// ipucu (en tehlikeli kaynak).
const DICT_KEY_SOURCE =
  /\.items\(\)|\.keys\(\)|for\s+\w+\s*,\s*\w+\s+in\s+\w+\.items|request\.|form\.get|args\.get|params\[|query\[/;

const isPython = (f: string) => /\.py$/.test(f);
const isTsJs = (f: string) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f);

// TS/JS template-literal shape: a SQL keyword followed DIRECTLY by an
// interpolation — `FROM ${tablo}`, `SET ${assignments}` — i.e. the identifier
// position. Value positions (`WHERE id = ${id}`) do NOT match: the keyword is
// followed by a column name, not `${`.
const TS_IDENT_POSITION =
  /\b(SET|FROM|JOIN|TABLE|INTO|UPDATE|ORDER\s+BY|GROUP\s+BY)\b\s*\$\{/i;
const TS_INPUT_SOURCE = /(request\.|req\.|params|query|body|searchParams|args\.)/i;

export const sqlIdentifierInjection: StaticRule = {
  id: "a03-sql-identifier-injection",
  title: "SQL column or table name built by string concatenation (identifier injection)",
  owasp: "A03:2021-Injection",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|conftest|fixtures?)/.test(file)) continue;
      if (!isPython(file) && !isTsJs(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (raw.trim().startsWith("#")) continue;
        const window = lines.slice(Math.max(0, i - 2), i + 3).join("\n");
        if (!SQL_STMT.test(window)) continue;

        // TS/JS BRANCH: template literal with an interpolation in identifier
        // position. Missed by the recall suite (rule used to be Python-only).
        if (isTsJs(file)) {
          if (!TS_IDENT_POSITION.test(raw)) continue;
          // allowlist-guarded identifiers are the correct pattern
          if (/allowlist|beyaz|whitelist|_COLUMNS|_SUTUN|\.includes\s*\(/i.test(window)) continue;
          const interpName = /\$\{([a-zA-Z_][\w]*)\}/.exec(raw);
          if (!interpName) continue; // only flag a simple identifier binding
          const ad = interpName[1];
          const girsel = TS_INPUT_SOURCE.test(window);
          if (!girsel) {
            const sabitGibi = /^[A-Z][A-Z0-9_]*$/.test(ad);
            const sqlParcasi = /(kosul|where|filter|clause|sql|cond|columns|sutun)/i.test(ad);
            if (sabitGibi || sqlParcasi) continue;
          }
          findings.push({
            ruleId: this.id,
            title: this.title,
            owasp: this.owasp,
            severity: girsel ? "high" : "medium",
            description:
              `${file}:${i + 1} interpolates a variable into a SQL identifier ` +
              `(SET/FROM/JOIN/table position) inside a template literal. Identifiers ` +
              `cannot be parameterised` +
              (girsel
                ? ` and the variable appears to come from external input — a value like ` +
                  `"users DROP TABLE x --" changes the statement's meaning.`
                : ` — confirm the source is not external input.`),
            evidence: [fileEvidence(file, i + 1, raw.trim().slice(0, 100))],
            remediation:
              "Constrain table/column names to a fixed ALLOWLIST map " +
              "(e.g. const TABLES = { orders: 'orders' }) and look the identifier up. " +
              "Never take an identifier straight from external input.",
          });
          break; // one finding per file is enough
        }

        // f-string SQL with interpolation in an identifier position
        if (!FSTRING_INTERP.test(raw) && !/\{[^}]+\}/.test(raw)) continue;
        if (!IDENT_POSITION.test(window)) continue;

        // Skip when it is protected by an allowlist or a fixed tuple
        if (/allowlist|beyaz|whitelist|_SUTUN|_COLUMNS|frozenset|in\s*\(/i.test(window)) {
          if (!DICT_KEY_SOURCE.test(window)) continue;
        }

        // FALSE-POSITIVE FILTERING: if the interpolated variable looks CONSTANT
        // (an UPPERCASE name = a module constant), or its name suggests a SQL
        // fragment assembled in code ("condition", "where", "filter"), then it is
        // NOT user input. E.g. f"... WHERE {HOME_CONDITION}" — HOME_CONDITION is a
        // code constant. Still inspect it when there is a dict-key source.
        const interpName = /\{([a-zA-Z_][\w]*)\}/.exec(raw);
        if (interpName && !DICT_KEY_SOURCE.test(window)) {
          const ad = interpName[1];
          const sabitGibi = /^[A-Z][A-Z0-9_]*$/.test(ad);            // EV_KOSULU
          const sqlParcasi = /(kosul|kosul_|ara_sql|where|filter|clause|sql|cond|kondisyon)/i.test(ad);
          if (sabitGibi || sqlParcasi) continue;
        }

        const dictKey = DICT_KEY_SOURCE.test(window);
        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: dictKey ? "high" : "medium",
          description:
            `${file}:${i + 1} builds a SQL identifier (a SET/FROM/ORDER BY column or ` +
            `table name) through string interpolation. Even when the value is parameterised, ` +
            `bile TANIMLAYICI parametrelenemez` +
            (dictKey
              ? ` and the interpolation appears to come from a dict key or external input — ` +
                `a key like "is_active=0 WHERE 1=1 --" can override the WHERE clause and hit every row.`
              : ` — confirm the source is not external input.`),
          evidence: [fileEvidence(file, i + 1, raw.trim().slice(0, 100))],
          remediation:
            "Constrain column and table names to a fixed ALLOWLIST " +
            "(e.g. frozenset({'name','price',...})), and silently skip any key " +
            "that is not on it. Never take an identifier straight from external input.",
        });
        break; // one finding per file is enough
      }
    }
    return findings;
  },
};
