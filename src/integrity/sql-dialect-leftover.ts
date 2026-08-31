import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A04 — a DIALECT LEFTOVER from a database migration.
 *
 * In a codebase that moved from SQLite to PostgreSQL (or from MySQL), function
 * calls specific to the old engine stay behind. The new engine does NOT have
 * that function, so every request running that query fails — usually silently,
 * because the code compiles, the tests never take that path, and the failure
 * only surfaces when someone presses that button.
 *
 * Real case: during an audit trail review, a search box used `instr()`.
 * PostgreSQL has no such function; the search had NEVER worked. The box sat
 * there on screen and nobody had tried it. Had a security tool's FALSE positive
 * not pushed someone to read that line, it would still be there.
 */

/** Functions specific to other engines that do NOT exist in the target engine. */
const YABANCI: Record<string, Array<{ ad: string; source: string; karsilik: string }>> = {
  postgres: [
    { ad: "instr", source: "SQLite", karsilik: "position(alt IN metin) > 0 ya da LIKE" },
    { ad: "ifnull", source: "SQLite/MySQL", karsilik: "coalesce()" },
    { ad: "group_concat", source: "SQLite/MySQL", karsilik: "string_agg()" },
    { ad: "julianday", source: "SQLite", karsilik: "date arithmetic (date - date)" },
    { ad: "strftime", source: "SQLite", karsilik: "to_char()" },
    { ad: "last_insert_rowid", source: "SQLite", karsilik: "RETURNING id" },
    { ad: "randomblob", source: "SQLite", karsilik: "gen_random_bytes()" },
    { ad: "date_format", source: "MySQL", karsilik: "to_char()" },
    { ad: "str_to_date", source: "MySQL", karsilik: "to_timestamp()" },
    { ad: "curdate", source: "MySQL", karsilik: "current_date" },
    { ad: "unix_timestamp", source: "MySQL", karsilik: "extract(epoch from ...)" },
  ],
  mysql: [
    { ad: "instr", source: "SQLite", karsilik: "LOCATE()" },
    { ad: "julianday", source: "SQLite", karsilik: "TO_DAYS()" },
    { ad: "string_agg", source: "PostgreSQL", karsilik: "GROUP_CONCAT()" },
    { ad: "gen_random_uuid", source: "PostgreSQL", karsilik: "UUID()" },
    { ad: "to_char", source: "PostgreSQL", karsilik: "DATE_FORMAT()" },
  ],
  sqlite: [
    { ad: "string_agg", source: "PostgreSQL", karsilik: "group_concat()" },
    { ad: "gen_random_uuid", source: "PostgreSQL", karsilik: "generate it in the application" },
    { ad: "to_char", source: "PostgreSQL", karsilik: "strftime()" },
    { ad: "date_format", source: "MySQL", karsilik: "strftime()" },
  ],
};

/** Is this line a SQL context? Words like `typeof` and `printf` exist in JS too. */
const SQL_BAGLAMI =
  // Tam ifade anahtar kelimeleri…
  /\b(select|insert|update|delete|from|where|order\s+by|group\s+by|having|join)\b/i;

/**
 * A SQL FRAGMENT context.
 *
 * A query is not always a complete statement: in real code it is written as a
 * WHERE FRAGMENT such as `sql\`instr(...) > 0\`` with the word `WHERE` never
 * appearing. The first version looked only for complete statements and missed
 * the very line the rule was written for — the same mistake for a third time.
 */
const SQL_PARCASI = /\bsql\s*`|\bis\s+(not\s+)?null\b|\bilike\b|\bcoalesce\s*\(|\bcast\s*\(|::\w+/i;

/** Projenin hedef motoru. */
function motor(ctx: StaticContext): keyof typeof YABANCI | null {
  const bildirilen = ctx.project.stack.db;
  if (bildirilen === "postgres" || bildirilen === "neon" || bildirilen === "supabase" || bildirilen === "prisma") {
    return "postgres";
  }

  // Other declared engines have to count too. The first version knew only the
  // Postgres family, so a project declaring `stack.db: "sqlite"` was NOT
  // recognised at all.
  if (bildirilen === "sqlite") return "sqlite";
  if (bildirilen === "mysql") return "mysql";

  const paket = ctx.read("package.json") || "";
  if (/"(pg|postgres|@neondatabase\/serverless|drizzle-orm)"/.test(paket)
    && !/"better-sqlite3"/.test(paket)) return "postgres";
  if (/"mysql2?"/.test(paket)) return "mysql";
  if (/"better-sqlite3"/.test(paket)) return "sqlite";

  // THE JS ECOSYSTEM IS NOT THE ONLY ECOSYSTEM.
  //
  // Engine detection looked only at `package.json`: in a Python project the
  // target engine was never found and the rule silently never ran — even though
  // migrated Python harvesters are exactly where dialect leftovers are most
  // common. The second canary (SQLite/Python) caught this.
  if (ctx.grep(/^\s*import\s+(sqlite3|aiosqlite)\b|from\s+(sqlite3|aiosqlite)\s+import/m).length > 0)
    return "sqlite";
  if (ctx.grep(/^\s*import\s+(psycopg2?|asyncpg)\b|from\s+(psycopg2?|asyncpg)\s+import/m).length > 0)
    return "postgres";
  if (ctx.grep(/^\s*import\s+(pymysql|MySQLdb)\b/m).length > 0) return "mysql";

  return null;
}

export const sqlDialectLeftover: StaticRule = {
  id: "int-sql-dialect-leftover",
  title: "Dialect leftover from a database migration — the query fails at runtime",
  owasp: "A04:2021-Insecure Design",
  severity: "high",
  kind: "static",
  // NO PRECONDITIONS. The "js" declaration was WRONG: the rule also reads `.sql`
  // files, which is where dialect leftovers are most often found. In a Python +
  // SQL project it silently never ran.
  requires: [],
  confidence: "certain",
  run(ctx): Finding[] {
    const target = motor(ctx);
    if (!target) return [];

    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.(ts|tsx|js|jsx|mjs|cjs|sql)$/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        // In a SQL file every line is SQL; in code, only SQL-looking lines.
        if (!/\.sql$/.test(file) && !SQL_BAGLAMI.test(line) && !SQL_PARCASI.test(line)) continue;

        for (const { ad, source, karsilik } of YABANCI[target]) {
          if (!new RegExp(`\\b${ad}\\s*\\(`, "i").test(line)) continue;
          findings.push({
            ruleId: "int-sql-dialect-leftover",
            title: "Dialect leftover from a database migration — the query fails at runtime",
            owasp: "A04:2021-Insecure Design",
            severity: "high",
            confidence: "certain",
            description:
              `\`${file}:${i + 1}\` calls **${ad}()**, a ${source} function. The target engine is ` +
              `${target}, which has NO such function. Every request that runs this query fails with ` +
              `"function ${ad}(...) does not exist" — usually silently, because ` +
              "the code compiles, the tests never take that path, and the failure surfaces only when someone uses the feature.",
            evidence: [fileEvidence(file, i + 1, line.trim().slice(0, 140))],
            remediation: `Use ${karsilik} instead. Then write a test that ACTUALLY exercises the feature: ` +
              "a dialect leftover is invisible at compile time and only appears at runtime.",
          });
          break;
        }
      }
    }
    return findings;
  },
};
