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

describe("A05 — build-config: env değişkeni tanımsız", () => {
  it("BAD: kodda process.env.X var, .env.example'da yok → low bulgu", async () => {
    const f = await run({
      ".env.example": "NEXT_PUBLIC_API_URL=\nDATABASE_URL=\n",
      "lib/pay.ts": `const k = process.env.STRIPE_SECRET_KEY; const w = process.env.WEBHOOK_SECRET;`,
    });
    const env = f.find((x) => x.title.includes("tanımsız"));
    expect(env).toBeTruthy();
    expect(env!.severity).toBe("low");
    expect(env!.confidence).toBe("olası");
    expect(env!.description).toContain("STRIPE_SECRET_KEY");
    expect(env!.description).toContain("WEBHOOK_SECRET");
  });

  it("CLEAN: tüm env'ler .env.example'da tanımlı → env bulgusu YOK", async () => {
    const f = await run({
      ".env.example": "STRIPE_SECRET_KEY=\nDATABASE_URL=\n",
      "lib/pay.ts": `const k = process.env.STRIPE_SECRET_KEY; const d = process.env.DATABASE_URL;`,
    });
    expect(f.some((x) => x.title.includes("tanımsız"))).toBe(false);
  });

  it("built-in env (NODE_ENV, VERCEL_URL) → FP üretmez", async () => {
    const f = await run({
      ".env.example": "DATABASE_URL=\n",
      "lib/x.ts": `const e = process.env.NODE_ENV; const v = process.env.VERCEL_URL; const d = process.env.DATABASE_URL;`,
    });
    expect(f.some((x) => x.title.includes("tanımsız"))).toBe(false);
  });

  it("import.meta.env (Vite) da yakalanır", async () => {
    const f = await run(
      {
        ".env.example": "VITE_KNOWN=\n",
        "src/api.ts": `const u = import.meta.env.VITE_SUPABASE_URL; const k = import.meta.env.VITE_KNOWN;`,
      },
      { stack: { framework: "vite" } },
    );
    const env = f.find((x) => x.title.includes("tanımsız"));
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

describe("A05 — build-config: çözülemeyen relative import", () => {
  it("BAD: var olmayan ./missing importu → low bulgu", async () => {
    const f = await run({
      "src/index.ts": `import { foo } from "./missing"; foo();`,
    });
    const imp = f.find((x) => x.title.includes("Çözülemeyen"));
    expect(imp).toBeTruthy();
    expect(imp!.severity).toBe("low");
  });
  it("CLEAN: import gerçek dosyaya çözülüyor → bulgu YOK", async () => {
    const f = await run({
      "src/index.ts": `import { foo } from "./util"; foo();`,
      "src/util.ts": `export function foo(){}`,
    });
    expect(f.some((x) => x.title.includes("Çözülemeyen"))).toBe(false);
  });
  it("CLEAN: .js belirtilmiş ama .ts kaynağı var (NodeNext) → FP yok", async () => {
    const f = await run({
      "src/index.ts": `import { foo } from "./util.js"; foo();`,
      "src/util.ts": `export function foo(){}`,
    });
    expect(f.some((x) => x.title.includes("Çözülemeyen"))).toBe(false);
  });
  it("CLEAN: index barrel importu → FP yok", async () => {
    const f = await run({
      "src/app.ts": `import { x } from "./components"; x();`,
      "src/components/index.ts": `export const x = 1;`,
    });
    expect(f.some((x) => x.title.includes("Çözülemeyen"))).toBe(false);
  });
  it("CLEAN: css/asset importu → taranmadığı için FP yok", async () => {
    const f = await run({
      "src/app.tsx": `import "./styles.css"; import logo from "./logo.svg";`,
    });
    expect(f.some((x) => x.title.includes("Çözülemeyen"))).toBe(false);
  });
  it("CLEAN: ?query sonekli asset (Prisma .wasm?module) → FP yok", async () => {
    const f = await run({
      "src/db.ts": `import wasm from "./query_compiler_fast_bg.wasm?module"; export { wasm };`,
    });
    expect(f.some((x) => x.title.includes("Çözülemeyen"))).toBe(false);
  });
});

describe("A05 — build-config: tamamen temiz proje", () => {
  it("hiçbir sorun yok → bulgu YOK (FP taşkını yok)", async () => {
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
