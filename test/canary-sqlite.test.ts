import { describe, it, expect, beforeAll } from "vitest";
import { join } from "node:path";
import { scanProject } from "../src/core/engine.js";
import { allRules } from "../src/rules.js";

/**
 * THE SECOND CANARY — targeting SQLite / Python.
 *
 * The main canary is a Next + Supabase project. Some rules CANNOT be represented
 * in that context: the dialect-leftover rule needs a SQLite-targeting project,
 * the RLS rule needs Supabase — the two cannot live in one project.
 *
 * This canary found two real blind spots the moment it was set up:
 *  1. The `int-sql-dialect-leftover` and `a02-sensitive-data-plaintext` rules had
 *     a WRONG "js" precondition declared; both of them read `.sql` files. In a
 *     Python + SQL project they silently never ran — so the wrong declaration
 *     produced exactly the blindness it was meant to prevent.
 *  2. Target engine detection looked only at `package.json`: in a Python project
 *     the engine was never found and the rule never ran.
 */
const ROOT = join(import.meta.dirname ?? __dirname, "canary-sqlite");
let findings: Set<string>;

beforeAll(async () => {
  const rapor = await scanProject(
    { name: "canary-sqlite", path: ROOT, owned: false, stack: { framework: "node", db: "sqlite" } },
    allRules,
    { staticOnly: true, includeStandards: false, includeDeps: false },
  );
  findings = new Set(rapor.findings.map((f) => f.ruleId));
}, 60_000);

const yakalandi = (id: string) => findings.has(id);

describe("second canary — the SQLite/Python context", () => {
  it("dialect leftover: PostgreSQL functions in a SQLite project", () => {
    expect(yakalandi("int-sql-dialect-leftover")).toBe(true);
  });

  it("no lock wait in multi-writer SQLite", () => {
    expect(yakalandi("a04-sqlite-no-busy-timeout")).toBe(true);
  });

  it("external JSON parsed without a try", () => {
    expect(yakalandi("a04-unguarded-json-parse")).toBe(true);
  });

  it("the tool must not stay silent in this context", () => {
    expect(findings.size).toBeGreaterThanOrEqual(3);
  });
});
