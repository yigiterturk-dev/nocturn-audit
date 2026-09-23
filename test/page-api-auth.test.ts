import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { pageApiAuthDivergence } from "../src/integrity/page-api-auth-divergence.js";

/**
 * The page and the API diverging on their auth path.
 *
 * A server-rendered page CHOOSES its own auth call; the API being right does not
 * make the page right. Real case: a tenant portal page called `getPanelActor()`,
 * which returns null for a non-staff session — a signed-in tenant could not enter
 * their own portal. Because every portal test went through the API, the bug had
 * nowhere to surface.
 */

const AUTH = `
export async function getPanelActor() {
  const session = await cookies();
  return session ? { role: "admin" } : null;
}
export async function getPortalActor() {
  const session = await cookies();
  return session ? { role: "resident" } : null;
}`;

const run = (files: Record<string, string>) =>
  pageApiAuthDivergence.run(makeCtx(files)) as Array<{ severity: string; description: string }>;

describe("int — page/API auth divergence", () => {
  it("BAD: the page calls one helper, the API calls two", () => {
    const f = run({
      "lib/auth.ts": AUTH,
      "app/api/management/route.ts": `const actor = (await getPanelActor()) || (await getPortalActor());`,
      "app/resident/page.tsx": `const actor = await getPanelActor(); if (!actor) redirect("/gate");`,
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("getPortalActor");
    expect(f[0].description).toContain("tenant");
  });

  it("CLEAN: the page calls both as well", () => {
    const f = run({
      "lib/auth.ts": AUTH,
      "app/api/management/route.ts": `const actor = (await getPanelActor()) || (await getPortalActor());`,
      "app/resident/page.tsx": `const actor = (await getPanelActor()) || (await getPortalActor());`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a page that calls no auth at all is a public page", () => {
    // Public pages are not this rule's subject; otherwise every landing page would
    // be a finding.
    const f = run({
      "lib/auth.ts": AUTH,
      "app/api/x/route.ts": `const a = (await getPanelActor()) || (await getPortalActor());`,
      "app/kiraliklar/page.tsx": `export default function Page() { return <div>ilanlar</div>; }`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a STAFF page may call only the staff helper", () => {
    // The first version expected every page to match the API's widest set and
    // produced nine findings in one project, most of them wrong. An admin page
    // legitimately uses only the staff helper; that is correct design.
    const f = run({
      "lib/auth.ts": AUTH,
      "app/api/management/route.ts": `const a = (await getPanelActor()) || (await getPortalActor());`,
      "app/erisim/page.tsx": `const actor = await getPanelActor(); if (!actor) redirect("/gate");`,
      "app/operasyon/page.tsx": `const actor = await getPanelActor();`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: no verdict when no helper serves that subject", () => {
    // If the project has no notion of a portal, there is nothing to compare the
    // `/resident` page against.
    const f = run({
      "lib/auth.ts": `export async function getUser() { const s = await cookies(); return s; }
export async function getAdmin() { const s = await cookies(); return s; }`,
      "app/api/x/route.ts": `const u = await getUser();`,
      "app/resident/page.tsx": `const u = await getAdmin();`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: with a single auth helper in the project there is no divergence to speak of", () => {
    const f = run({
      "lib/auth.ts": `export async function getUser() { const s = await cookies(); return s; }`,
      "app/api/x/route.ts": `const u = await getUser();`,
      "app/panel/page.tsx": `const u = await getUser();`,
    });
    expect(f.length).toBe(0);
  });
});
