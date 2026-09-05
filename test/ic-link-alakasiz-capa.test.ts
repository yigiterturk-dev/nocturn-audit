import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { icLinkAlakasizCapa } from "../src/integrity/ic-link-alakasiz-capa.js";

/**
 * GERÇEK VAKA (gelecekfinans.com, 4 ve 5 Eylül 2026 — ikisi de canlıda bulundu):
 * otomatik iç bağlantı üreticisi çapa metnini kelime uzunluğuna göre seçiyordu.
 * "Enflasyon nedir nasıl hesaplanır" yazısında "nasıl" (5 harf) ilgisiz iki
 * makaleye bağlandı; bir gün sonra DASK haberinde "yalnızca" (8 harf) bir
 * altcoin haberine, "devam edecek" bir e-ihracat haberine bağlandı. İlk
 * düzeltme jenerik kelime LİSTESİ olduğu için arıza yeni kelimelerle döndü.
 */

const run = (files: Record<string, string>) =>
  icLinkAlakasizCapa.run(makeCtx(files)) as Array<{ severity: string; description: string }>;

describe("int — iç bağlantı çapası/hedefi konuya bakmadan seçiliyor", () => {
  it("BAD: çapa metni yalnızca kelime uzunluğuna göre seçiliyor", () => {
    const f = run({
      "lib/bot/linker.ts": `export function terms(article: { title: string }): string[] {
  return article.title.split(/[\\s:,;.!?]+/).filter((w) => w.length > 4);
}
export function inject(html: string, article: { slug: string; title: string }): string {
  for (const term of terms(article)) {
    if (html.includes(term)) return html.replace(term, \`<a href="/\${article.slug}">\${term}</a>\`);
  }
  return html;
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
    expect(f[0].description).toContain("ÇAPA METNİ");
  });

  it("BAD: bağlantı hedefi aday havuzundan sırayla seçiliyor", () => {
    const f = run({
      "lib/bot/linker.ts": `let idx = 0;
export function fill(html: string, pool: Array<{ slug: string; title: string }>): string {
  return html.replace(/\\[DAHILI_LINK\\]/g, () => {
    const target = pool[idx % pool.length];
    idx++;
    return \`<a href="/\${target.slug}">\${target.title}</a>\`;
  });
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("HEDEF");
  });

  it("CLEAN: çapa yapısal olarak süzülüyor, hedef konu örtüşmesiyle seçiliyor", () => {
    const f = run({
      "lib/bot/linker.ts": `const FUNCTION_WORDS = new Set(["yalnızca", "sadece", "tüm"]);
const FINITE_VERB = /(ecek|acak|ıyor|dı|mış)$/;
function isContentWord(word: string): boolean {
  return word.length >= 5 && !FUNCTION_WORDS.has(word) && !FINITE_VERB.test(word);
}
export function relevanceScore(html: string, article: { title: string }): number {
  return article.title.split(/\\s+/).filter(isContentWord).filter((w) => html.includes(w)).length;
}
export function inject(html: string, pool: Array<{ slug: string; title: string }>): string {
  const target = pool
    .map((item) => ({ item, score: relevanceScore(html, item) }))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score)[0]?.item;
  if (!target) return html;
  return \`\${html}<a href="/\${target.slug}">\${target.title}</a>\`;
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: link üretmeyen dosyadaki uzunluk filtresi bu arıza değil", () => {
    const f = run({
      "lib/bot/summary.ts": `export function wordCount(title: string): number {
  return title.split(/\\s+/).filter((w) => w.length > 4).length;
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: modulo ile sıralı seçim ama liste sayfası, bağlantı üretimi yok", () => {
    const f = run({
      "lib/rotate.ts": `export function nextBanner(banners: string[], i: number): string {
  return banners[i % banners.length];
}`,
    });
    expect(f.length).toBe(0);
  });
});
