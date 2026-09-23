import { existsSync } from "node:fs";
import { createRequire } from "node:module";

// Load node:sqlite with a RUNTIME require: vite/vitest static import analysis
// tries to resolve the 'sqlite' module and fails. createRequire bypasses that.
const _require = createRequire(import.meta.url);
type DatabaseSyncCtor = new (path: string, opts?: { readOnly?: boolean }) => {
  prepare(sql: string): { all(...p: unknown[]): unknown[]; get(...p: unknown[]): unknown };
  exec(sql: string): void;
  close(): void;
};
/**
 * Loaded LAZILY, and this matters.
 *
 * `node:sqlite` only exists from Node 22.5. At module top level this `require`
 * threw at import time — and because the CLI imports this module, the WHOLE
 * tool refused to start on Node 20, the version its own `engines` field
 * promises. Only the `invariants` command needs SQLite; nothing else should
 * pay for it.
 *
 * The public CI caught this on the first run, which is the entire argument for
 * running the gate on the oldest supported version rather than the newest.
 */
function loadDatabaseSync(): DatabaseSyncCtor {
  try {
    return _require("node:sqlite").DatabaseSync as DatabaseSyncCtor;
  } catch {
    throw new Error(
      "The `invariants` command needs the built-in node:sqlite module, which " +
        `requires Node 22.5 or newer (running ${process.version}). ` +
        "Every other command works on Node 20.",
    );
  }
}

/**
 * RUNTIME INVARIANT mode (deterministic, no LLM).
 *
 * Static rules read code; this mode measures DATA. It catches the "the system
 * says it is fine and it is not" cases a regex cannot see, straight from the
 * live database. The first invariant: ORPHAN ROWS — the runtime counterpart of
 * the fk-cascade-off static rule. Even when the schema declares ON DELETE
 * CASCADE, SQLite's foreign-key enforcement is off by default, so deleting a
 * parent leaves the children orphaned; you can only see that by looking at data.
 */

export interface InvariantFinding {
  invariant: string;
  severity: "low" | "medium" | "high";
  detail: string;
  count?: number;
}

interface FkRow { table: string; from: string; to: string; parent: string; }

export function runInvariants(dbPath: string): InvariantFinding[] {
  if (!existsSync(dbPath)) {
    return [{ invariant: "db-missing", severity: "high",
      detail: `Database file not found: ${dbPath} — nothing was measured (this is "could not look", not zero).` }];
  }
  const DatabaseSync = loadDatabaseSync();
  const db = new DatabaseSync(dbPath, { readOnly: true });
  const findings: InvariantFinding[] = [];
  try {
    const tablolar = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    ).all() as Array<{ name: string }>;

    const fkler: FkRow[] = [];
    for (const t of tablolar) {
      const rows = db.prepare(`PRAGMA foreign_key_list(${JSON.stringify(t.name).replace(/"/g, "")})`).all() as Array<{ table: string; from: string; to: string }>;
      for (const r of rows) {
        fkler.push({ table: t.name, from: r.from, to: r.to || "id", parent: r.table });
      }
    }

    // Count orphans per FK: the child's fk is set but has no match in the parent.
    let toplamYetim = 0;
    for (const r of fkler) {
      try {
        const q = `SELECT COUNT(*) AS n FROM "${r.table}" c
                   WHERE c."${r.from}" IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM "${r.parent}" p WHERE p."${r.to}" = c."${r.from}")`;
        const row = db.prepare(q).get() as { n: number };
        if (row.n > 0) {
          toplamYetim += row.n;
          findings.push({
            invariant: "yetim-kayit",
            severity: row.n > 50 ? "high" : "medium",
            count: row.n,
            detail: `${r.table}.${r.from} → ${r.parent}.${r.to}: ${row.n} orphan row(s) ` +
              `(child rows with no parent). Their existence proves foreign-key enforcement was ` +
              `OFF at write time (the cascade never ran). A maintenance job should sweep them.`,
          });
        }
      } catch { /* skip this FK if the query could not be built */ }
    }

    if (fkler.length > 0 && toplamYetim === 0) {
      findings.push({ invariant: "yetim-kayit", severity: "low",
        detail: `Scanned ${fkler.length} foreign-key relation(s); no orphan rows (clean).` });
    }
  } finally {
    db.close();
  }
  return findings;
}
