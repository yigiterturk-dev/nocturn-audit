import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — multi-writer SQLite with no busy_timeout → "database is locked".
 *
 * In SQLite, while one writer holds the lock a second writer does NOT wait
 * unless busy_timeout is set (the default is 0) — it throws "database is
 * locked" immediately. When a background job (scraper, cron) writes roughly
 * once a second and the dashboard reads and writes on every request, a
 * collision is only a matter of time. WAL mode saves readers, not two WRITERS.
 *
 * Real case: none of nine connection points set busy_timeout; a scraper wrote
 * every ~30 seconds while the dashboard wrote on every request.
 * The fix: PRAGMA busy_timeout=5000 on every connection.
 *
 * This rule flags a file containing a sqlite3.connect(...) call when
 * busy_timeout never appears in that file.
 */

const SQLITE_CONNECT = /sqlite3?\.connect\s*\(|new\s+Database\s*\(|better-sqlite3|aiosqlite\.connect/i;
/**
 * A SQLite busy timeout signal. CAREFUL: only the ones that belong to SQLITE.
 *
 * There used to be a general pattern like `timeout\s*[:=]\s*\d`, and an
 * `urlopen(u, timeout=120)` in one project — an HTTP timeout — was mistaken for
 * a SQLite busy_timeout. The whole file was skipped as "already setting it" and
 * a REAL finding vanished silently. The CI gate caught it: that is precisely a
 * false negative, the most dangerous kind of mistake this tool can make.
 *
 * A general `timeout=` counts ONLY on the CONNECT CALL's own line
 * (`sqlite3.connect(path, timeout=30)` really does set the busy timeout).
 */
const BUSY_TIMEOUT = /busy_timeout|busyTimeout|PRAGMA\s+busy/i;
const CONNECT_TIMEOUT_ARG =
  /(sqlite3?\.connect|aiosqlite\.connect|new\s+Database)\s*\([^)]*timeout\s*[:=]\s*\d/i;

const isSourceLike = (f: string) =>
  /\.(py|js|ts|mjs|cjs)$/.test(f) && !/(test|spec|conftest|migrations?)/.test(f);

export const sqliteNoBusyTimeout: StaticRule = {
  id: "a04-sqlite-no-busy-timeout",
  title: "Multi-writer SQLite without busy_timeout (database is locked risk)",
  owasp: "A04:2021-Insecure Design",
  severity: "low",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // Does the project use SQLite, and is there a background writer (cron,
    // scraper, worker, timer)? Without both, the risk is low.
    const connectHits = ctx.grep(SQLITE_CONNECT);
    if (connectHits.length === 0) return findings;

    const hasBackgroundWriter =
      ctx.grep(/cron|scheduler|APScheduler|schedule\.|celery|worker|scraper|systemd|OnCalendar|BackgroundTasks/i)
        .length > 0;

    // Per file: there is a connect but no busy_timeout
    const flagged = new Set<string>();
    for (const m of connectHits) {
      if (!isSourceLike(m.file)) continue;
      if (flagged.has(m.file)) continue;
      const content = ctx.read(m.file);
      if (!content) continue;
      // Does the file really set a SQLite busy timeout?
      if (BUSY_TIMEOUT.test(content) || CONNECT_TIMEOUT_ARG.test(content)) continue;
      flagged.add(m.file);

      // A READ-ONLY file does not need busy_timeout: lock contention happens
      // between two WRITERS. For a SELECT-only maintenance or reporting tool the
      // warning is noise.
      const yaziyor = /(INSERT\s+INTO|INSERT\s+OR|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|DROP\s+TABLE|REPLACE\s+INTO|VACUUM\s+INTO)/i.test(content);
      if (!yaziyor) continue;

      // Does this file run REGULARLY (timer/cron/scheduler/while), or is it a
      // one-shot CLI tool? A regular writer is real risk; a one-shot manual tool
      // is low.
      const duzenli = /(OnCalendar|cron|scheduler|schedule\.|while\s+True|APScheduler|BackgroundTasks|systemd)/i.test(content)
        || /(main\.py|app\.py|server|worker|scraper|_service)/i.test(m.file);

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        // Writes + runs regularly (or is the main app) -> real risk;
        // writes + one-shot CLI tool -> low.
        severity: (hasBackgroundWriter && duzenli) ? "medium" : "low",
        description:
          `${m.file} opens a SQLite connection without setting busy_timeout. ` +
          `SQLite defaults to 0: while one writer holds the lock, a second writer does not ` +
          `wait — it throws "database is locked" immediately.` +
          (hasBackgroundWriter
            ? ` This project has a background writer (cron, scraper or worker), so a collision is only a matter of time.`
            : ` It looks single-writer today, but concurrent requests would still be risky.`),
        evidence: [fileEvidence(m.file, m.line, "sqlite connect")],
        remediation:
          "Run `PRAGMA busy_timeout=5000` (ms) on every connection, and use " +
          "`PRAGMA journal_mode=WAL` for multiple readers. Set both in one shared " +
          "connection helper.",
      });
    }
    return findings;
  },
};
