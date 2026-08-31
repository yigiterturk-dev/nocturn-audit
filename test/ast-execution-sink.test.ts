import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { dangerousEval } from "../src/static/dangerous-eval.js";

const run = (files: Record<string, string>) =>
  dangerousEval.run(makeCtx(files)) as Array<{ title: string; severity: string }>;

/**
 * One run produced 117 findings from this rule; ~100 of them were `regex.exec()`
 * and better-sqlite3's `db.exec()`. Both carry the `exec(` pattern and neither
 * executes a command. Text search cannot make that distinction; the tree can.
 */
describe("A03 — command execution: tree confirmation", () => {
  it("CLEAN: RegExp.exec is not command execution", () => {
    const f = run({
      "src/lib/analyze.ts": `const re = /(\\d+)/g;
export function ayikla(text: string) {
  const m = re.exec(text);
  return m?.[1] ?? null;
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: better-sqlite3 db.exec() runs SQL, not a shell", () => {
    const f = run({
      "src/lib/auth.ts": `import Database from "better-sqlite3";
const db = new Database("app.db");
db.exec("BEGIN IMMEDIATE;");
db.exec(AUTH_SCHEMA);`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: `spawn` from a different module does not count", () => {
    const f = run({
      "src/lib/worker.ts": `import { spawn } from "redux-saga/effects";
export function* saga() { yield spawn(baskaIs); }`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: exec from child_process counts", () => {
    const f = run({
      "src/lib/run.ts": `import { exec } from "node:child_process";
export function calistir(cmd: string) { exec(cmd); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("BAD: counts even when imported under an alias", () => {
    const f = run({
      "src/lib/run.ts": `import { execSync as calistir } from "child_process";
export function kur() { calistir("npm ci"); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("BAD: a namespace import (cp.spawn) counts", () => {
    const f = run({
      "src/lib/run.ts": `import * as cp from "node:child_process";
export function baslat() { cp.spawn("ls", ["-la"]); }`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("BAD: child_process taken via require counts", () => {
    const f = run({
      "scripts/kur.js": `const { execSync } = require("child_process");
execSync("npm ci");`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("CLEAN: the word 'spawn' in a README is not code", () => {
    const f = run({
      "README.md": "| last commit | opens a subprocess with spawn(...) | exec(",
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: the word 'eval' inside text is not a call", () => {
    const f = run({
      "src/lib/notlar.ts": `export const mesaj = "eval( kullanmayin";
export const baska = { evaluation: 1 };`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: a real eval call counts — and produces ONE finding", () => {
    const f = run({
      "src/lib/dinamik.ts": `export function calistir(kod: string) { return eval(kod); }`,
    });
    // Two signatures under the same `kind` (eval / new Function) were attaching to
    // one call: a single call became two findings.
    expect(f.length).toBe(1);
    expect(f[0].title).toMatch(/eval\(\)/);
  });

  it("BAD: new Function is a separate finding, not conflated with eval", () => {
    const f = run({
      "src/lib/dinamik.ts": `export const topla = new Function("a", "b", "return a + b");`,
    });
    expect(f.length).toBe(1);
    expect(f[0].title).toMatch(/new Function/);
  });
});

import { unguardedJsonParse } from "../src/static/unguarded-json-parse.js";

const runJson = (files: Record<string, string>) =>
  unguardedJsonParse.run(makeCtx(files)) as Array<{ severity: string }>;

/**
 * A text walk was wrong in both directions: a 40-line window missed large try
 * blocks, and a line mistaken for `function` cut the search short.
 */
describe("A04 — unguarded JSON.parse: try detection via the tree", () => {
  it("CLEAN: a try counts as a guard even when it is more than 40 lines away", () => {
    const dolgu = Array.from({ length: 45 }, (_, i) => `    const ara${i} = ${i};`).join("\n");
    const f = runJson({
      "src/lib/oku.ts": `export function oku(raw: string) {
  try {
${dolgu}
    const v = JSON.parse(raw);
    return v;
  } catch {
    return null;
  }
}`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: a finding when there is no try (external data kills the job with one bad record)", () => {
    const f = runJson({
      "src/lib/oku.ts": `export function oku(raw: string) {
  const v = JSON.parse(raw);
  return v;
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("CLEAN: a generated Prisma client is not project code", () => {
    const f = runJson({
      "src/generated/prisma/internal/class.ts": `config.runtimeDataModel = JSON.parse(veri);`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: an outer try does not count as guarding an inner function's body → finding", () => {
    const f = runJson({
      "src/lib/oku.ts": `export function dis(raw: string) {
  try {
    return liste.map(function ic(x) { return JSON.parse(x); });
  } catch { return null; }
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});

import { massAssignment } from "../src/static/mass-assignment.js";

const runMass = (files: Record<string, string>) =>
  massAssignment.run(makeCtx(files)) as Array<{ severity: string }>;

/**
 * Searching for taint with `\b${v}\b` is dangerous: a short variable name like
 * `id` also matches the PROPERTY name in `reviewer?.id`. That is exactly what
 * happened in one project and produced 10 false mass-assignment findings.
 */
describe("A01 — mass assignment: taint carrying must not trip on a property name", () => {
  it("CLEAN: the `reviewer?.id` property is not the tainted `id` variable", () => {
    const f = runMass({
      "server.ts": `app.post('/x/:id', async (req, res) => {
  const id = req.params.id;
  const kayit = { ...(mevcut.metadata || {}), decision: 'ok', reviewerUserId: reviewer?.id || null };
  await supabase.from('logs').update({ action: 'onay', metadata: kayit }).eq('id', id);
});`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: the finding stands when a tainted variable really is spread", () => {
    const f = runMass({
      "server.ts": `app.post('/x', async (req, res) => {
  const gelen = req.body;
  const kayit = { ...gelen, olusturuldu: new Date() };
  await supabase.from('logs').insert({ ...kayit });
});`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("BAD: formData → Object.fromEntries → DB (the blindness the canary caught)", () => {
    const f = runMass({
      "app/api/kayit/route.ts": `export async function POST(req) {
  const form = await req.formData();
  const kayit = Object.fromEntries(form);
  await db.insert(kullanicilar).values({ ...kayit });
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});
