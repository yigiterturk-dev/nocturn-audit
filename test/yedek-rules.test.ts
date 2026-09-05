import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { yedekKanitiYok } from "../src/static/yedek-kaniti-yok.js";

const canli = { project: { owned: true, url: "https://ornek.com" } };

describe("A08 — hesap dışı yedek kanıtı", () => {
  it("BAD: canlı + veritabanı var, yedek izi yok → INFO bulgu", () => {
    const f = yedekKanitiYok.run(makeCtx({
      "package.json": `{ "dependencies": { "drizzle-orm": "^0.30.0" } }`,
      "db/index.ts": `const sql = neon(process.env.DATABASE_URL!);`,
    }, canli));
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
  });

  it("BAD: yedek betiği var ama ZAMANLANMAMIŞ → bulgu (elle yedek, alınmadığı gün yoktur)", () => {
    const f = yedekKanitiYok.run(makeCtx({
      "db/index.ts": `const sql = neon(process.env.DATABASE_URL!);`,
      "scripts/yedek-al.sh": `#!/usr/bin/env bash\npg_dump "$DATABASE_URL" -Fc -f "$DOSYA"`,
    }, canli));
    expect(f.length).toBe(1);
    expect(f[0].description).toMatch(/ZAMANLANDIĞINA dair iz yok/);
  });

  it("CLEAN: yedek betiği + cron zamanlaması → bulgu YOK", () => {
    const f = yedekKanitiYok.run(makeCtx({
      "db/index.ts": `const sql = neon(process.env.DATABASE_URL!);`,
      "ops/yedek.sh": `#!/usr/bin/env bash\npg_dump "$DATABASE_URL" -Fc -f "$D"\n# cron: 15 3 * * * root /opt/yedek.sh`,
    }, canli));
    expect(f.length).toBe(0);
  });

  it("CLEAN: canlı DEĞİL (url yok) → gürültü üretme", () => {
    const f = yedekKanitiYok.run(makeCtx({
      "db/index.ts": `const sql = neon(process.env.DATABASE_URL!);`,
    }, { project: { owned: true } }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: bize ait değilse konumuz değil", () => {
    const f = yedekKanitiYok.run(makeCtx({
      "db/index.ts": `const sql = neon(process.env.DATABASE_URL!);`,
    }, { project: { owned: false, url: "https://baskasinin.com" } }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: kalıcı veri tutmayan statik site → bulgu YOK", () => {
    const f = yedekKanitiYok.run(makeCtx({
      "app/page.tsx": `export default function Page() { return <h1>Merhaba</h1>; }`,
    }, canli));
    expect(f.length).toBe(0);
  });

  it("CLEAN: 'backup' kelimesi bir bağımlılık adında geçiyor diye yedek sayılmaz", () => {
    // Yalnız gerçek bir yedek ARACI sayılır; aksi halde kural kendini kandırır.
    const f = yedekKanitiYok.run(makeCtx({
      "db/index.ts": `const sql = neon(process.env.DATABASE_URL!);`,
      "package.json": `{ "dependencies": { "some-backup-ui-lib": "^1.0.0" } }`,
    }, canli));
    expect(f.length).toBe(1);   // hâlâ bulgu: gerçek yedek aracı yok
  });
});
