import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { pathTraversal } from "../src/static/path-traversal.js";
import { redos } from "../src/static/redos.js";
import { jwtAlgNone } from "../src/static/jwt-alg-none.js";
import { prototypePollution } from "../src/static/prototype-pollution.js";

describe("A01 — path traversal", () => {
  it("CLEAN: a fixed literal path is not a finding", () => {
    const f = pathTraversal.run(makeCtx({
      "src/fs.ts": `import { readFileSync } from "node:fs";\nconst data = readFileSync("/etc/hosts", "utf8");`,
    }));
    expect(f.length).toBe(0);
  });

  it("BAD: fs.readFile with a user-supplied path → finding", () => {
    const f = pathTraversal.run(makeCtx({
      "app/api/route.ts": `import { readFileSync } from "node:fs";\nexport async function GET(req) { const p = req.query.file; return readFileSync(p); }`,
    }));
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });

  it("CLEAN: a non-fs module named readFile is not a finding", () => {
    const f = pathTraversal.run(makeCtx({
      "src/x.ts": `import { readFile } from "some-lib";\nreadFile(userInput);`,
    }));
    expect(f.length).toBe(0);
  });
});

describe("A03 — ReDoS", () => {
  it("CLEAN: new RegExp with a literal pattern is not a finding", () => {
    const f = redos.run(makeCtx({
      "src/r.ts": `const re = new RegExp("^[a-z]+$");`,
    }));
    expect(f.length).toBe(0);
  });

  it("BAD: new RegExp built from user input → finding", () => {
    const f = redos.run(makeCtx({
      "app/api/route.ts": `export async function GET(req) { const pat = req.query.pattern; return new RegExp(pat); }`,
    }));
    expect(f.length).toBe(1);
  });
});

describe("A07 — JWT alg:none", () => {
  it("CLEAN: algorithms pinned to HS256 is not a finding", () => {
    const f = jwtAlgNone.run(makeCtx({
      "src/auth.ts": `import jwt from "jsonwebtoken";\njwt.verify(token, secret, { algorithms: ["HS256"] });`,
    }));
    expect(f.length).toBe(0);
  });

  it("BAD: algorithms: ['none'] → finding", () => {
    const f = jwtAlgNone.run(makeCtx({
      "src/auth.ts": `import jwt from "jsonwebtoken";\njwt.verify(token, secret, { algorithms: ["none"] });`,
    }));
    expect(f.length).toBe(1);
    expect(f[0].confidence).toBe("certain");
  });

  it("BAD: empty algorithms array → finding", () => {
    const f = jwtAlgNone.run(makeCtx({
      "src/auth.ts": `import jwt from "jsonwebtoken";\njwt.verify(token, secret, { algorithms: [] });`,
    }));
    expect(f.length).toBe(1);
  });
});

describe("A03 — prototype pollution", () => {
  it("CLEAN: a normal object assignment is not a finding", () => {
    const f = prototypePollution.run(makeCtx({
      "src/x.ts": `const o = {}; o.name = "x";`,
    }));
    expect(f.length).toBe(0);
  });

  it("BAD: assignment to __proto__ → finding", () => {
    const f = prototypePollution.run(makeCtx({
      "src/x.ts": `const o = {}; o["__proto__"] = payload;`,
    }));
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });

  it("BAD: merge of user input → finding", () => {
    const f = prototypePollution.run(makeCtx({
      "app/api/route.ts": `export async function POST(req) { const body = await req.json(); return merge({}, body); }`,
    }));
    expect(f.length).toBe(1);
  });
});

describe("a01-path-traversal — istek yuzeyi sarti", () => {
  it("CLEAN: CLI aracinda (istek yuzeyi YOK) → NO finding", () => {
    // Portfoyde bu tek varsayim 15 sahte "high" uretti. Yol gecisi ancak yolu
    // SALDIRGAN secebiliyorsa aciktir; argv'yi veren zaten kabuga sahiptir.
    const f = pathTraversal.run(makeCtx({
      "src/cli.ts": `import { readFileSync } from "node:fs";\nconst hedef = process.argv[2];\nexport function tara() { return readFileSync(hedef, "utf8"); }`,
    }));
    expect(f.length).toBe(0);
  });
  it("BAD: ayni sink bir ROTA dosyasinda → bulgu (kural korelmedi)", () => {
    const f = pathTraversal.run(makeCtx({
      "app/api/dosya/route.ts": `import { readFileSync } from "node:fs";\nexport async function GET(req) { const ad = req.query.ad; return readFileSync(ad, "utf8"); }`,
    }));
    expect(f.length).toBeGreaterThan(0);
  });
});
