import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { unboundSessionFallthrough } from "../src/integrity/unbound-session-fallthrough.js";

/**
 * An unbound session falls through to a default identity.
 *
 * Real case: five sessions opened with a shared password were still alive after
 * personal accounts had been created. The gate rejected NEW logins, but because
 * those sessions had an empty `subjectKind` they could not enter the bound-account
 * branch and fell through to the default identity below — as admin.
 */

const run = (files: Record<string, string>) =>
  unboundSessionFallthrough.run(makeCtx(files)) as Array<{ severity: string; description: string }>;

const BAGLI_DAL = `
export async function getPanelActor() {
  const session = await currentSession();
  if (session?.subjectKind && session.actorEmail) {
    return resolveActor(session.actorEmail);
  }`;

describe("int — an unbound session", () => {
  it("BAD: with no binding the function carries on and produces an identity", () => {
    const f = run({
      "lib/auth.ts": `${BAGLI_DAL}
  const configuredEmail = process.env.PANEL_USER_EMAIL || "admin@local";
  return { email: configuredEmail, role: "admin" };
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].description).toContain("subjectKind");
  });

  it("CLEAN: the unbound session is rejected EXPLICITLY", () => {
    const f = run({
      "lib/auth.ts": `
export async function getPanelActor() {
  const session = await currentSession();
  if (session && !session.subjectKind) return null;
  if (session?.subjectKind && session.actorEmail) {
    return resolveActor(session.actorEmail);
  }
  const configuredEmail = process.env.PANEL_USER_EMAIL || "admin@local";
  return { email: configuredEmail, role: "admin" };
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: no identity is produced after the binding check", () => {
    // If the function returns nothing when there is no binding, there is no problem.
    const f = run({
      "lib/auth.ts": `${BAGLI_DAL}
  return null;
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: silent in a project with no auth helper", () => {
    const f = run({ "lib/util.ts": `export function topla(a, b) { return a + b; }` });
    expect(f.length).toBe(0);
  });
});

describe("int — an unbound session (fail-closed default)", () => {
  it("CLEAN: the fallthrough lands on the least-privilege 'viewer' → NO finding (fail-closed)", () => {
    const f = run({
      "lib/auth.ts": `${BAGLI_DAL}
  }
  return 'viewer';
}`,
    });
    expect(f.length).toBe(0);
  });
  it("BAD: a fallthrough landing on 'admin' → still a finding (elevated privilege)", () => {
    const f = run({
      "lib/auth.ts": `${BAGLI_DAL}
  }
  return { email: process.env.PANEL_USER_EMAIL || "x", role: "admin" };
}`,
    });
    expect(f.length).toBe(1);
  });
});
