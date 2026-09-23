import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { buildConfig } from "../src/static/build-config.js";
import type { Finding } from "../src/core/finding.js";

async function run(
  files: Record<string, string>,
  overrides?: Parameters<typeof makeCtx>[1],
): Promise<Finding[]> {
  return Promise.resolve(buildConfig.run(makeCtx(files, overrides)));
}

describe("A05 — build-config: undocumented env variable", () => {
  it("BAD: kodda process.env.X var, .env.example'da yok → low bulgu", async () => {
    const f = await run({
      ".env.example": "NEXT_PUBLIC_API_URL=\nDATABASE_URL=\n",
      "lib/pay.ts": `const k = process.env.STRIPE_SECRET_KEY; const w = process.env.WEBHOOK_SECRET;`,
    });
    const env = f.find((x) => x.title.includes("undocumented"));
    expect(env).toBeTruthy();
    expect(env!.severity).toBe("low");
    expect(env!.confidence).toBe("likely");
    expect(env!.description).toContain("STRIPE_SECRET_KEY");
    expect(env!.description).toContain("WEBHOOK_SECRET");
  });

  it("CLEAN: every env is declared in .env.example → NO env finding", async () => {
    const f = await run({
      ".env.example": "STRIPE_SECRET_KEY=\nDATABASE_URL=\n",
      "lib/pay.ts": `const k = process.env.STRIPE_SECRET_KEY; const d = process.env.DATABASE_URL;`,
    });
    expect(f.some((x) => x.title.includes("undocumented"))).toBe(false);
  });

  it("built-in envs (NODE_ENV, VERCEL_URL) → produce no FP", async () => {
    const f = await run({
      ".env.example": "DATABASE_URL=\n",
      "lib/x.ts": `const e = process.env.NODE_ENV; const v = process.env.VERCEL_URL; const d = process.env.DATABASE_URL;`,
    });
    expect(f.some((x) => x.title.includes("undocumented"))).toBe(false);
  });

  it("import.meta.env (Vite) is caught too", async () => {
    const f = await run(
      {
        ".env.example": "VITE_KNOWN=\n",
        "src/api.ts": `const u = import.meta.env.VITE_SUPABASE_URL; const k = import.meta.env.VITE_KNOWN;`,
      },
      { stack: { framework: "vite" } },
    );
    const env = f.find((x) => x.title.includes("undocumented"));
    expect(env).toBeTruthy();
    expect(env!.description).toContain("VITE_SUPABASE_URL");
  });
});

describe("A05 — build-config: TS strict / build script", () => {
  it("BAD: strict:false → info bulgu", async () => {
    const f = await run({
      "tsconfig.json": `{ "compilerOptions": { "strict": false } }`,
    });
    const ts = f.find((x) => x.title.includes("strict"));
    expect(ts).toBeTruthy();
    expect(ts!.severity).toBe("info");
  });
  it("CLEAN: strict:true → bulgu YOK", async () => {
    const f = await run({
      "tsconfig.json": `{ "compilerOptions": { "strict": true } }`,
    });
    expect(f.some((x) => x.title.includes("strict"))).toBe(false);
  });

  it("BAD: next projesi build script yok → low bulgu", async () => {
    const f = await run(
      { "package.json": `{ "name": "x", "scripts": { "dev": "next dev" } }` },
      { stack: { framework: "next" } },
    );
    expect(f.some((x) => x.title.includes("build script"))).toBe(true);
  });
  it("CLEAN: build script var → bulgu YOK", async () => {
    const f = await run(
      { "package.json": `{ "name": "x", "scripts": { "build": "next build" } }` },
      { stack: { framework: "next" } },
    );
    expect(f.some((x) => x.title.includes("build script"))).toBe(false);
  });
});

describe("A05 — build-config: unresolvable relative import", () => {
  it("BAD: var olmayan ./missing importu → low bulgu", async () => {
    const f = await run({
      "src/index.ts": `import { foo } from "./missing"; foo();`,
    });
    const imp = f.find((x) => x.title.includes("Unresolvable"));
    expect(imp).toBeTruthy();
    expect(imp!.severity).toBe("low");
  });
  it("CLEAN: the import resolves to a real file → NO finding", async () => {
    const f = await run({
      "src/index.ts": `import { foo } from "./util"; foo();`,
      "src/util.ts": `export function foo(){}`,
    });
    expect(f.some((x) => x.title.includes("Unresolvable"))).toBe(false);
  });
  it("CLEAN: .js was written but a .ts source exists (NodeNext) → no FP", async () => {
    const f = await run({
      "src/index.ts": `import { foo } from "./util.js"; foo();`,
      "src/util.ts": `export function foo(){}`,
    });
    expect(f.some((x) => x.title.includes("Unresolvable"))).toBe(false);
  });
  it("CLEAN: index barrel importu → FP yok", async () => {
    const f = await run({
      "src/app.ts": `import { x } from "./components"; x();`,
      "src/components/index.ts": `export const x = 1;`,
    });
    expect(f.some((x) => x.title.includes("Unresolvable"))).toBe(false);
  });
  it("CLEAN: a css/asset import → no FP because it is not scanned", async () => {
    const f = await run({
      "src/app.tsx": `import "./styles.css"; import logo from "./logo.svg";`,
    });
    expect(f.some((x) => x.title.includes("Unresolvable"))).toBe(false);
  });
  it("CLEAN: ?query sonekli asset (Prisma .wasm?module) → FP yok", async () => {
    const f = await run({
      "src/db.ts": `import wasm from "./query_compiler_fast_bg.wasm?module"; export { wasm };`,
    });
    expect(f.some((x) => x.title.includes("Unresolvable"))).toBe(false);
  });
});

describe("A05 — build-config: tamamen temiz proje", () => {
  it("no problems at all → NO finding (no FP flood)", async () => {
    const f = await run(
      {
        "package.json": `{ "name": "x", "scripts": { "build": "next build" } }`,
        "tsconfig.json": `{ "compilerOptions": { "strict": true } }`,
        ".env.example": "DATABASE_URL=\n",
        "src/index.ts": `import { u } from "./util"; export const d = process.env.DATABASE_URL; u();`,
        "src/util.ts": `export function u(){}`,
      },
      { stack: { framework: "next" } },
    );
    expect(f.length).toBe(0);
  });
});
