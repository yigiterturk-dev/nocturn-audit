import { describe, it, expect } from "vitest";
import { ayristir } from "../src/core/ast.js";
import {
  bodyShape,
  findHandlers,
  hasIdentityGate,
  isRouteFile,
} from "../src/core/route.js";

const ast = (kod: string, file = "app/api/x/route.ts") => ayristir(file, kod)!;

/**
 * The access-control rules asked the same three questions with three separate
 * regexes and all three were wrong in different ways. Shared ground ends the
 * habit of fixing the same bug in three places.
 */
describe("rota analizi — ortak zemin", () => {
  it("only a ROOT app/ counts as a route (examples/ is never served)", () => {
    expect(isRouteFile("app/api/notes/route.ts")).toBe(true);
    expect(isRouteFile("src/app/api/notes/route.ts")).toBe(true);
    expect(isRouteFile("pages/api/notes.ts")).toBe(true);
    expect(isRouteFile("examples/d1/app/api/notes/route.ts")).toBe(false);
    expect(isRouteFile("lib/api/helper.ts")).toBe(false);
  });

  it("finds handlers written as functions and as arrow functions", () => {
    const h1 = findHandlers(ast(`export async function POST(req){ return Response.json({}); }`));
    expect(h1.map((h) => h.metod)).toEqual(["POST"]);
    expect(h1[0].writer).toBe(true);

    const h2 = findHandlers(ast(`export const DELETE = async (req) => Response.json({});`));
    expect(h2.map((h) => h.metod)).toEqual(["DELETE"]);

    const h3 = findHandlers(ast(`export async function GET(){ return Response.json({}); }`));
    expect(h3[0].writer).toBe(false);
  });

  it("a non-exported function with the same name is not a handler", () => {
    const h = findHandlers(ast(`async function POST(req){ return null; }`));
    expect(h.length).toBe(0);
  });

  it("identity gates: requireX, getServerSession and a permission list", () => {
    expect(hasIdentityGate(ast(`export async function POST(){ const u = await getUser(); }`).source)).toBe(true);
    expect(
      hasIdentityGate(
        ast(`export async function GET(){ const { permissions } = await getUserRoleData(); if(!permissions.includes("orders")) return; }`).source,
      ),
    ).toBe(true);
    // the shape that produced the IDOR false positive in one project
    expect(
      hasIdentityGate(ast(`export async function GET(){ if(!permissions.includes("orders")) return; }`).source),
    ).toBe(true);
    expect(hasIdentityGate(ast(`export async function POST(){ await db.insert(t).values({}); }`).source)).toBe(false);
  });

  it("body format: json / form / none", () => {
    expect(bodyShape(ast(`export async function POST(req){ const b = await req.json(); }`).source)).toBe("json");
    expect(bodyShape(ast(`export async function POST(req){ const f = await req.formData(); }`).source)).toBe("form");
    // `Response.json({...})` is WRITING a response, not READING a body. The first
    // version confused them and this test enshrined the mistake as "correct".
    expect(bodyShape(ast(`export async function POST(){ return Response.json({}); }`).source)).toBe("yok");
  });
});

import { makeCtx } from "./helpers.js";
import { openRedirect } from "../src/static/open-redirect.js";

const runYon = (files: Record<string, string>) =>
  openRedirect.run(makeCtx(files)) as Array<{ severity: string }>;

/**
 * File-wide taint is a disaster in large files: in one project's 6000-line
 * server.ts, a single `const url = req.query.x` SOMEWHERE made EVERY
 * `redirect(url)` call in the WHOLE file tainted. An Instagram OAuth redirect
 * was declared an "open redirect" that way.
 */
describe("A01 — open redirect: taint is function scoped", () => {
  it("CLEAN: a tainted `url` in another function does not poison this one", () => {
    const f = runYon({
      "server.ts": `app.get('/a', (req, res) => {
  const url = req.query.next;
  console.log(url);
});
app.get('/b', (req, res) => {
  const url = buildInstagramAuthUrl({ appId: IG_APP_ID(), redirectUri: igRedirectUri(), state });
  res.redirect(url);
});`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: a target derived from input in the same function → finding", () => {
    const f = runYon({
      "server.ts": `app.get('/git', (req, res) => {
  const url = req.query.next;
  res.redirect(url);
});`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("BAD: redirecting with input directly → finding", () => {
    const f = runYon({
      "app/api/git/route.ts": `export async function GET(req) {
  return Response.redirect(new URL(req.url).searchParams.get("next"), 302);
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});
