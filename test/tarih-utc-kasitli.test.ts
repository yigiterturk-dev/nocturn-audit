import { describe, it, expect } from "vitest";
import { tarihUtcGunKaymasi } from "../src/static/tarih-utc-gun-kaymasi.js";
import { makeCtx } from "./helpers.js";

const run = (files: Record<string, string>) => tarihUtcGunKaymasi.run(makeCtx(files));

describe("a04-tarih-utc-gun-kaymasi — kasıtlı UTC ayırt etme", () => {
  it("BAD: yerel gece yarısı + toISOString → kayar (bulgu üretmeli)", async () => {
    const f = await run({
      "src/rapor.ts": `function son7gun(n: number): string[] {\n  const d = new Date(iso + "T00:00:00");\n  d.setDate(d.getDate() + n);\n  return d.toISOString().slice(0, 10);\n}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("CLEAN: T00:00:00Z tabanı + setUTCDate — kasıtlı UTC aritmetiği (gerçek vaka: bir marka yonetim SaaS inclusiveDateKeys)", async () => {
    const f = await run({
      "server_lib/metaDaily.ts": `export function inclusiveDateKeys(until: string, days: number): string[] {\n  const end = Date.parse(\`\${until}T00:00:00Z\`);\n  return Array.from({ length: days }, (_, i) =>\n    new Date(end - (days - 1 - i) * 86_400_000).toISOString().slice(0, 10)\n  );\n}`,
      "server_lib/weeklyReport.ts": `function shiftDateString(ymd: string, days: number): string {\n  const dt = new Date(\`\${ymd}T00:00:00Z\`);\n  dt.setUTCDate(dt.getUTCDate() + days);\n  return dt.toISOString().slice(0, 10);\n}`,
    });
    expect(f).toHaveLength(0);
  });

  it("CLEAN: Intl.DateTimeFormat ile bölge belirtilmiş biçimlendirme", async () => {
    const f = await run({
      "src/tarih.ts": `export function istanbulGunu(d: Date): string {\n  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Istanbul' }).format(d);\n}`,
    });
    expect(f).toHaveLength(0);
  });

  it("BAD: Z'siz gece yarısı parse'ı hâlâ yakalanır — Z ayrımı güvenlik değil doğruluk şartı", async () => {
    const f = await run({
      "src/kopiu.ts": `function tarihKayar(): string {\n  const d = new Date(\`2026-01-01T00:00:00\`);\n  d.setDate(5);\n  return d.toISOString().slice(0, 10);\n}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});
