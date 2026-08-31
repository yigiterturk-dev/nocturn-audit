import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { gateConditionTooBroad } from "../src/integrity/gate-condition-too-broad.js";

/**
 * The closing condition is broader than the gate.
 *
 * Real case: a shared password was a STAFF setup path and its closing condition
 * was "does any login credential exist". An operator who invited a TENANT before
 * creating their own account was locked out of the panel completely — the shared
 * password was now rejected, they had no account, and there was no way back in.
 */

const TUR = `
export type Subject = { subjectKind: "staff" | "resident" };
export function bySubjectKind(kind: string) { return kind; }`;

const run = (files: Record<string, string>) =>
  gateConditionTooBroad.run(makeCtx(files)) as Array<{ severity: string; description: string }>;

describe("int — the closing condition is too broad", () => {
  it("BAD: the gate decision rests on an unfiltered 'does any exist' helper", () => {
    const f = run({
      "lib/types.ts": TUR,
      "lib/identity/credentials.ts": `export async function hasAnyCredential() {
  return Boolean(await first(db.select({ id: creds.id }).from(creds)));
}`,
      "app/api/gate/route.ts": `const kisiselGiris = await hasAnyCredential();
if (kisiselGiris) { return verifyLogin(body); }`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].description).toContain("hasAnyCredential");
  });

  it("CLEAN: the condition is narrow when the helper filters by KIND", () => {
    const f = run({
      "lib/types.ts": TUR,
      "lib/identity/credentials.ts": `export async function hasStaffCredential() {
  return Boolean(await first(db.select({ id: creds.id }).from(creds).where(eq(creds.subjectKind, "staff"))));
}`,
      "app/api/gate/route.ts": `const kisiselGiris = await hasStaffCredential();`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: with no kind distinction in the project, 'too broad' has no meaning", () => {
    const f = run({
      "lib/identity/credentials.ts": `export async function hasAnyCredential() { return true; }`,
      "app/api/gate/route.ts": `const v = await hasAnyCredential();`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a count in a file with no gate context is not a finding", () => {
    // `hasAnyOrder()` is a reporting question, not a gate decision.
    const f = run({
      "lib/types.ts": TUR,
      "lib/report.ts": `const any = await hasAnyOrder(); return any ? "full" : "empty";`,
    });
    expect(f.length).toBe(0);
  });
});
