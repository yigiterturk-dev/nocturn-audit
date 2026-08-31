import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
type DbCtor = new (p: string) => { exec(s: string): void; close(): void };

// node:sqlite only exists from Node 22.5. The tool supports Node 20, where the
// `invariants` command is unavailable by design — so these tests skip rather
// than fail, and the CI gate can still run on the oldest supported version.
// The require must be LAZY: at module top level it would throw before
// `describe.skipIf` ever got the chance to skip.
let DatabaseSync: DbCtor | null = null;
try {
  DatabaseSync = createRequire(import.meta.url)("node:sqlite").DatabaseSync as DbCtor;
} catch {
  DatabaseSync = null;
}
const sqliteAvailable = DatabaseSync !== null;
import { runInvariants } from "../src/invariants.js";

describe.skipIf(!sqliteAvailable)("invariants — orphan rows", () => {
  it("catches an orphan row created while FKs were off", () => {
    const dir = mkdtempSync(join(tmpdir(), "inv-"));
    const dbPath = join(dir, "t.db");
    const db = new DatabaseSync!(dbPath);
    db.exec("PRAGMA foreign_keys=OFF");
    db.exec("CREATE TABLE parent(id INTEGER PRIMARY KEY)");
    db.exec("CREATE TABLE child(id INTEGER, pid INTEGER REFERENCES parent(id))");
    db.exec("INSERT INTO parent VALUES (1)");
    db.exec("INSERT INTO child VALUES (1,1),(2,99),(3,88)");
    db.close();

    const findings = runInvariants(dbPath);
    const yetim = findings.filter((b) => b.invariant === "yetim-kayit" && (b.count ?? 0) > 0);
    expect(yetim.length).toBe(1);
    expect(yetim[0].count).toBe(2);
    rmSync(dir, { recursive: true, force: true });
  });
  it("returns clean (low) when there are no orphans", () => {
    const dir = mkdtempSync(join(tmpdir(), "inv-"));
    const dbPath = join(dir, "t.db");
    const db = new DatabaseSync!(dbPath);
    db.exec("CREATE TABLE parent(id INTEGER PRIMARY KEY)");
    db.exec("CREATE TABLE child(id INTEGER, pid INTEGER REFERENCES parent(id))");
    db.exec("INSERT INTO parent VALUES (1)");
    db.exec("INSERT INTO child VALUES (1,1)");
    db.close();
    const findings = runInvariants(dbPath);
    expect(findings.every((b) => (b.count ?? 0) === 0)).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });
  it("does not return 0 when the DB is absent, it says 'could not look'", () => {
    const findings = runInvariants("/yok/olan/yol.db");
    expect(findings[0].invariant).toBe("db-missing");
    expect(findings[0].severity).toBe("high");
  });
});
