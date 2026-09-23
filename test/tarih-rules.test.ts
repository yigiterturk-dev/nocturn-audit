import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { tarihUtcGunKaymasi } from "../src/static/tarih-utc-gun-kaymasi.js";

describe("A04 — tarih toISOString gün kayması", () => {
  it("BAD: yerel gece yarısı + toISOString().slice(0,10) → bulgu (certain)", () => {
    const f = tarihUtcGunKaymasi.run(makeCtx({
      "lib/utils.ts":
        `export function addDaysISO(iso, days) {\n` +
        `  const d = new Date(iso + "T00:00:00");\n` +
        `  d.setDate(d.getDate() + days);\n` +
        `  return d.toISOString().slice(0, 10);\n}`,
    }));
    expect(f.length).toBe(1);
    expect(f[0].confidence).toBe("certain");
  });

  it("BAD: new Date().toISOString().slice(0,10) → 'bugün' UTC gününden (likely)", () => {
    const f = tarihUtcGunKaymasi.run(makeCtx({
      "lib/x.ts": `const bugun = new Date().toISOString().slice(0, 10);`,
    }));
    expect(f.length).toBe(1);
    expect(f[0].confidence).toBe("likely");
  });

  it("BAD: ay anahtarı slice(0,7) → bulgu", () => {
    const f = tarihUtcGunKaymasi.run(makeCtx({
      "lib/rapor.ts":
        `const d = new Date(y, m - 1, 1);\n` +
        `d.setMonth(d.getMonth());\n` +
        `const key = d.toISOString().slice(0, 7);`,
    }));
    expect(f.length).toBe(1);
    expect(f[0].description).toMatch(/AY/);
  });

  it("CLEAN: Date.UTC ile kasıtlı UTC aritmetiği bulgu DEĞİL", () => {
    const f = tarihUtcGunKaymasi.run(makeCtx({
      "lib/plan.ts":
        `export function addDays(iso, days) {\n` +
        `  const [y, m, d] = iso.split("-").map(Number);\n` +
        `  return new Date(Date.UTC(y, m - 1, d + days)).toISOString().slice(0, 10);\n}`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: tam zaman damgası (kesme yok) bulgu DEĞİL", () => {
    const f = tarihUtcGunKaymasi.run(makeCtx({
      "lib/log.ts": `const kayit = { createdAt: new Date().toISOString() };`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: YORUM içindeki örnek kod bulgu DEĞİL", () => {
    // Hatayı düzeltmiş bir ekip ne yaptığını yorumda anlatır; onu suçlamak
    // aracın güvenilirliğini bitirir.
    const f = tarihUtcGunKaymasi.run(makeCtx({
      "lib/utils.ts":
        `// ESKİ HALİ: new Date().toISOString().slice(0, 10) → UTC günü, yanlıştı.\n` +
        `/* d.setDate(...); return d.toISOString().slice(0, 10); */\n` +
        `export const todayISO = () => bicim.format(new Date());`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: Intl ile bölge sabitlenmiş biçimlendirme bulgu DEĞİL", () => {
    const f = tarihUtcGunKaymasi.run(makeCtx({
      "lib/utils.ts":
        `const b = new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Istanbul" });\n` +
        `export const todayISO = () => b.format(new Date());`,
    }));
    expect(f.length).toBe(0);
  });

  it("KOPYA: aynı hata üç dosyada da ayrı ayrı yakalanır", () => {
    // Asıl sinsi kısım buydu: yardımcı düzeltildi ama kopyaları bozuk kaldı.
    const govde = `const today = new Date().toISOString().slice(0, 10);`;
    const f = tarihUtcGunKaymasi.run(makeCtx({
      "lib/store.tsx": govde,
      "lib/data/mutations.ts": govde,
      "lib/data/seed-db.ts": govde,
    }));
    expect(f.length).toBe(3);
  });
});

describe("A02 — sırrı OKUYAN komut sır değildir", () => {
  it("CLEAN: kabuk betiğinde .env'den token okuyan satır bulgu DEĞİL", async () => {
    const { hardcodedSecrets } = await import("../src/static/hardcoded-secrets.js");
    const f = hardcodedSecrets.run(makeCtx({
      "ops/bekci.sh":
        `T="$(grep -m1 -E '^TELEGRAM_(BOT_)?TOKEN=' /root/jarvis/.env 2>/dev/null | cut -d= -f2-)"`,
    }));
    expect(f.length).toBe(0);
  });

  it("BAD: gerçekten gömülü bir anahtar hâlâ yakalanır", async () => {
    const { hardcodedSecrets } = await import("../src/static/hardcoded-secrets.js");
    const f = hardcodedSecrets.run(makeCtx({
      "src/config.ts": `const api_key = "aB3xQ9zK7mPw2LrT5vNc8HjF";`,
    }));
    expect(f.length).toBe(1);
  });
});
