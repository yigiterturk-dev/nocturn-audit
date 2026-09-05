import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — the SQLite schema declares ON DELETE CASCADE but the foreign_keys
 * PRAGMA is never enabled → the cascade SILENTLY does nothing and orphan rows pile up.
 *
 * In SQLite, foreign-key enforcement is OFF BY DEFAULT per connection. Even when
 * the schema says `REFERENCES ... ON DELETE CASCADE`, without
 * `PRAGMA foreign_keys = ON` on every connection the cascade never runs: deleting
 * a parent row leaves the children ORPHANED. If dashboard counters count orphans
 * the metrics inflate, and the orphaned data accumulates forever.
 *
 * Real case: three tables referenced a listing id, some of them with ON DELETE
 * CASCADE written out, but foreign_keys was never enabled; 10 orphans were
 * measured in production in one of them.
 * The fix: PRAGMA foreign_keys=ON plus a daily orphan sweep.
 *
 * This rule flags a SQLite project whose schema declares CASCADE/REFERENCES
 * while the foreign_keys PRAGMA is enabled NOWHERE.
 */

const SQLITE = /sqlite3?\.connect\s*\(|aiosqlite\.connect|new\s+Database\s*\(|better-sqlite3/i;

/**
 * Lockfiles LIE about the dialect. A lockfile lists the OPTIONAL PEERS of every
 * package: drizzle-orm supports a dozen drivers, so `better-sqlite3` appears in
 * package-lock.json of a project that only ever talks to Postgres. Treating that
 * as "this is a SQLite project" produced a false MEDIUM on a Neon/Postgres app.
 * A dialect claim must come from code the project actually runs.
 */
const KILIT_DOSYASI = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json|poetry\.lock|Gemfile\.lock|composer\.lock)$/i;

/**
 * Explicit "this project is NOT SQLite" signals. If the project connects to a
 * server database, `ON DELETE CASCADE` is enforced by the engine and the whole
 * premise of this rule (per-connection PRAGMA) does not apply.
 */
const SUNUCU_VERITABANI =
  /neon\(|@neondatabase|drizzle-orm\/pg-core|drizzle-orm\/mysql-core|from\s+["']pg["']|require\(["']pg["']\)|postgres:\/\/|postgresql:\/\/|mysql:\/\/|psycopg2|asyncpg|mongoose/i;
const FK_DECLARE = /REFERENCES\s+\w+|ON\s+DELETE\s+CASCADE|ON\s+DELETE\s+SET\s+NULL/i;
const FK_PRAGMA = /PRAGMA\s+foreign_keys\s*=?\s*(ON|1)|foreign_keys\s*=\s*(ON|1|True)|pragma\s*\(\s*['"]foreign_keys/i;

export const fkCascadeOff: StaticRule = {
  id: "a04-fk-cascade-off",
  title: "SQLite declares CASCADE but never enables the foreign_keys PRAGMA (orphan rows)",
  owasp: "A04:2021-Insecure Design",
  severity: "low",
  kind: "static",
  // Without a SQL schema or migration file the FK state CANNOT BE READ — to say
  // the cascade is dead you first have to see the table definition.
  requires: ["sql"],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // Is this a SQLite project? Lockfile hits DO NOT COUNT (see KILIT_DOSYASI).
    const sqliteHits = ctx
      .grep(SQLITE)
      .filter((m) => !KILIT_DOSYASI.test(m.file.replace(/\\/g, "/")));
    if (sqliteHits.length === 0) return findings;

    // Does the project talk to a SERVER database? Then the engine enforces the
    // cascade and this rule has nothing to say — say nothing rather than guess.
    if (ctx.grep(SUNUCU_VERITABANI).some((m) => !KILIT_DOSYASI.test(m.file.replace(/\\/g, "/")))) {
      return findings;
    }

    // Does the schema declare REFERENCES / ON DELETE CASCADE anywhere?
    const declHits = ctx.grep(FK_DECLARE);
    if (declHits.length === 0) return findings;

    // Is foreign_keys enabled ANYWHERE in the project?
    // Even one place is enough (it may be a shared connection helper); then it is
    // not silent and this rule must not raise a false alarm.
    if (ctx.grep(FK_PRAGMA).length > 0) return findings;

    // Show the first declaration point as evidence.
    const first = declHits.find((m) => /\.(py|js|ts|sql|rb|go)$/i.test(m.file)) ?? declHits[0];

    findings.push({
      ruleId: this.id,
      title: this.title,
      owasp: this.owasp,
      severity: "medium",
      description:
        `The schema declares ON DELETE CASCADE / REFERENCES (e.g. ${first.file}:` +
        `${first.line}) but nothing in the project ever runs \`PRAGMA foreign_keys = ON\`. ` +
        `In SQLite, foreign-key enforcement is OFF by default per connection: ` +
        `deleting a parent row does not cascade, so child rows are ORPHANED and ` +
        `accumulate silently. If dashboard counters count orphans, the metrics inflate too.`,
      evidence: [fileEvidence(first.file, first.line, "ON DELETE CASCADE / REFERENCES")],
      remediation:
        "Run `PRAGMA foreign_keys = ON` on every connection, from one shared " +
        "connection helper. Extra defence: (1) have dashboard counters JOIN to " +
        "exclude orphans; (2) run a periodic job that sweeps orphaned rows.",
    });
    return findings;
  },
};
