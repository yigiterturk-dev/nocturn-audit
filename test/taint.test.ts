import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { buildTaintIndex, isTainted } from "../src/core/taint.js";
import { cagrilariGez } from "../src/core/ast.js";
import { pathTraversal } from "../src/static/path-traversal.js";

describe("cross-file taint", () => {
  it("a value built in ANOTHER file is tainted (the call site shows no req.)", () => {
    const ctx = makeCtx({
      "lib/input.ts": `export function getPath(req) { return req.query.file; }`,
      "app/api/route.ts": `import { getPath } from "../../lib/input";\nimport { readFileSync } from "node:fs";\nexport async function GET(req) { const p = getPath(req); return readFileSync(p); }`,
    });
    const index = buildTaintIndex(ctx);
    const ast = ctx.ast("app/api/route.ts")!;
    // find the readFileSync call and check its first argument
    let tainted = false;
    cagrilariGez(ast, (c: any) => {
      const text = c.getText(ast.source);
      if (text.startsWith("readFileSync")) {
        tainted = isTainted(ast, c.arguments[0], index);
      }
    });
    expect(tainted).toBe(true);
  });

  it("a sanitized value is NOT tainted", () => {
    const ctx = makeCtx({
      "lib/safe.ts": `export function safePath(p) { return path.basename(p); }`,
      "app/api/route.ts": `import { safePath } from "../../lib/safe";\nimport { readFileSync } from "node:fs";\nexport async function GET(req) { const p = safePath(req.query.file); return readFileSync(p); }`,
    });
    const index = buildTaintIndex(ctx);
    const ast = ctx.ast("app/api/route.ts")!;
    let tainted = true;
    cagrilariGez(ast, (c: any) => {
      const text = c.getText(ast.source);
      if (text.startsWith("readFileSync")) {
        tainted = isTainted(ast, c.arguments[0], index);
      }
    });
    expect(tainted).toBe(false);
  });

  it("path-traversal catches a cross-file tainted path", () => {
    const f = pathTraversal.run(makeCtx({
      "lib/input.ts": `export function getPath(req) { return req.query.file; }`,
      "app/api/route.ts": `import { getPath } from "../../lib/input";\nimport { readFileSync } from "node:fs";\nexport async function GET(req) { const p = getPath(req); return readFileSync(p); }`,
    }));
    expect(f.length).toBe(1);
  });
});
