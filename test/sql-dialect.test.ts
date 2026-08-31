import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { sqlDialectLeftover } from "../src/integrity/sql-dialect-leftover.js";

/**
 * A dialect leftover.
 *
 * Real case: in a codebase that moved from SQLite to PostgreSQL, the audit
 * trail's search box used `instr()`. PG has no such function; the search had
 * NEVER worked and nobody had tried it. The code compiled, the tests never took
 * that path, and the failure existed only at runtime.
 */

const run = (files: Record<string, string>, stack?: Record<string, string>) =>
  sqlDialectLeftover.run(makeCtx(files, { stack: stack as never })) as Array<{
    severity: string; description: string; confidence?: string;
  }>;

describe("int — dialect leftover", () => {
  it("BAD: instr() in a PostgreSQL project → certain high", () => {
    const f = run({
      "package.json": `{"dependencies":{"pg":"^8","drizzle-orm":"^0.3"}}`,
      "lib/audit.ts": "sql`instr(lower(summary), lower(${terim})) > 0 AND id IS NOT NULL`",
    }, { db: "postgres" });
    expect(f.length).toBe(1);
    expect(f[0].confidence).toBe("certain");
    expect(f[0].description).toContain("instr()");
    expect(f[0].description).toContain("SQLite");
  });

  it("BAD: a leftover in a .sql file is caught too", () => {
    const f = run({
      "package.json": `{"dependencies":{"pg":"^8"}}`,
      "db/rapor.sql": "SELECT group_concat(ad) FROM kisiler;",
    }, { db: "postgres" });
    expect(f.length).toBe(1);
  });

  it("CLEAN: instr() is the correct function in a SQLite project", () => {
    // NOTE: makeCtx defaults the stack to `db: "supabase"` — i.e. postgres. The
    // engine looks at the DECLARED stack first, so the test has to override it
    // explicitly. I skipped that at first and three tests failed for the wrong
    // reason.
    // The same call is fine on the right engine. A rule cannot pass judgement
    // without knowing the engine — when it does not know, it stays silent.
    const f = run({
      "package.json": `{"dependencies":{"better-sqlite3":"^9"}}`,
      "lib/audit.ts": "db.prepare(`SELECT * FROM x WHERE instr(a, b) > 0`)",
    }, { db: "unknown" });
    expect(f.length).toBe(0);
  });

  it("CLEAN: motor bilinmiyorsa sessiz", () => {
    const f = run({ "lib/x.ts": "SELECT instr(a,b) FROM t" }, { db: "unknown" });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a line with no SQL context — `typeof` exists in JS too", () => {
    // SQL kelimeleri aranmasa `printf`/`typeof` gibi adlar JS kodunda
    // would produce constant false positives.
    const f = run({
      "package.json": `{"dependencies":{"pg":"^8"}}`,
      "lib/util.ts": "const t = ifnull(a, b); // a helper function, not SQL",
    }, { db: "postgres" });
    expect(f.length).toBe(0);
  });

  it("a PostgreSQL function is caught in a SQLite project too (the reverse direction)", () => {
    const f = run({
      "package.json": `{"dependencies":{"better-sqlite3":"^9"}}`,
      "db/x.sql": "SELECT string_agg(ad, ',') FROM kisiler;",
    }, { db: "unknown" });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("PostgreSQL");
  });
});
