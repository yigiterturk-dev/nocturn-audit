import { describe, it, expect } from "vitest";
import {
  pislikSkoru,
  pislikEtiketi,
  emptyCounts,
  type SeverityCounts,
} from "../src/core/severity.js";

const counts = (partial: Partial<SeverityCounts>): SeverityCounts => ({
  ...emptyCounts(),
  ...partial,
});

describe("pislikSkoru", () => {
  it("0 bulgu = 0 pislik", () => {
    expect(pislikSkoru(emptyCounts()).score).toBe(0);
  });

  it("ham toplamı sabit ölçeğe oturtur (×2, tavan 100)", () => {
    // 1 kritik (10) + 2 yüksek (12) = raw 22 → pislik 44
    expect(pislikSkoru(counts({ critical: 1, high: 2 })).score).toBe(44);
    // 5 kritik = 100 tavan
    expect(pislikSkoru(counts({ critical: 5 })).score).toBe(100);
    expect(pislikSkoru(counts({ critical: 50 })).score).toBe(100);
  });

  it("karşılaştırılabilir: aynı dağılım farklı projelerde aynı pisi verir", () => {
    const a = pislikSkoru(counts({ critical: 2, high: 3, medium: 4 }));
    const b = pislikSkoru(counts({ critical: 2, high: 3, medium: 4 }));
    expect(a.score).toBe(b.score);
    expect(a.raw).toBe(2 * 10 + 3 * 6 + 4 * 3);
  });

  it("ölçülemeyen kural varsa KISMİ işaretler — 0 bile temiz sayılmaz", () => {
    const full = pislikSkoru(emptyCounts());
    expect(full.partial).toBe(false);
    expect(full.label).toBe("tertemiz");

    const partial = pislikSkoru(emptyCounts(), 5);
    expect(partial.partial).toBe(true);
    expect(partial.score).toBe(0);
    expect(partial.label).toBe("tertemiz (kısmi ölçüm)");
  });

  it("etiket bantları sıralı ve kapsayıcı", () => {
    expect(pislikEtiketi(0)).toBe("tertemiz");
    expect(pislikEtiketi(5)).toBe("tozlu");
    expect(pislikEtiketi(15)).toBe("kirli");
    expect(pislikEtiketi(45)).toBe("pis");
    expect(pislikEtiketi(70)).toBe("çok pis");
    expect(pislikEtiketi(100)).toBe("biyolojik tehlike");
  });
});
