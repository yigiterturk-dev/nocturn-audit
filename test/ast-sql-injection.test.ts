import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { sqlInjection } from "../src/static/sql-injection.js";

const run = (files: Record<string, string>) =>
  sqlInjection.run(makeCtx(files)) as Array<{ severity: string; confidence?: string }>;

/**
 * As a text rule this produced 11 findings, nearly all false: a `.select()`
 * chain, a `for (let from = 0; ...)`, and worst of all Drizzle's tagged `sql``
 * template — the SOLUTION to injection was being reported as injection. The
 * difference is syntactic: a tagged template becomes a bind parameter, a template
 * handed to a raw query call does not.
 */
describe("A03 — SQL injection: tagged template versus raw query", () => {
  it("CLEAN: the Drizzle/postgres.js tagged template is parameterised", () => {
    const f = run({
      "src/db/q.ts": "export const r = await sql`SELECT * FROM users WHERE id = ${id}`;",
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: an ORM chain (.select/.from/.where) is not SQL text", () => {
    const f = run({
      "src/lib/list.ts": `export const r = await db.select({ id: contacts.id }).from(contacts).where(eq(contacts.id, id));`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a loop containing the word 'from' is not SQL", () => {
    const f = run({
      "scripts/import.mjs": `for (let from = 0; ; from += 1000) { console.log(from); }`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: constant SQL text (no variables) is not a finding", () => {
    const f = run({
      "src/db/q.ts": `await db.query("SELECT id FROM users WHERE active = true");`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: an interpolated template handed to a raw query call → finding", () => {
    const f = run({
      "src/db/q.ts": "export async function g(id) { return db.query(`SELECT * FROM users WHERE id = ${id}`); }",
    });
    expect(f.length).toBe(1);
  });

  it("BAD: CERTAIN and high when request input appears in the text", () => {
    const f = run({
      "app/api/u/route.ts":
        "export async function GET(req) { const q = req.nextUrl.searchParams.get('q'); return db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`); }",
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].confidence).toBe("certain");
  });

  it("BAD: a query built by string concatenation → finding", () => {
    const f = run({
      "src/db/q.ts": `await client.execute("SELECT * FROM t WHERE id = " + id);`,
    });
    expect(f.length).toBe(1);
  });

  it("BAD: $queryRawUnsafe parametrelemeyi atlar", () => {
    const f = run({
      "src/db/q.ts": "await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${id}`);",
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: a generated Prisma client is not project code", () => {
    const f = run({
      "src/generated/prisma/internal/ns.ts": "await db.query(`SELECT * FROM t WHERE id = ${id}`);",
    });
    expect(f.length).toBe(0);
  });
});

import { sensitiveDataPlaintext } from "../src/static/sensitive-data-plaintext.js";

const runHassas = (files: Record<string, string>) =>
  sensitiveDataPlaintext.run(makeCtx(files)) as Array<{ severity: string }>;

/**
 * The "name: type" shape can be a COLUMN or a PARAMETER in JS/TS. The rule could
 * not tell them apart and reported `function createAnthropicClient(apiKey: string)`
 * as "apiKey stored in plaintext". A parameter is not storage.
 */
describe("A02 — sensitive data: a parameter is not storage", () => {
  it("CLEAN: a function parameter (apiKey: string) is not a finding", () => {
    const f = runHassas({
      "lib/asistan/anthropic-istemci.ts": `function anthropicIstemciOlustur(apiKey: string): LLMIstemci {
  return { cagir: (x) => x };
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: an accessToken parameter is not a finding either", () => {
    const f = runHassas({
      "server_lib/gsc.ts": `function authHeaders(accessToken: string): Record<string, string> {
  return { Authorization: "Bearer " + accessToken };
}`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: an iban text column in a Drizzle schema → finding (compliance note)", () => {
    const f = runHassas({
      "src/db/schema.ts": `export const firms = pgTable("firms", {
  id: uuid("id"),
  iban: text("iban"),
});`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});
