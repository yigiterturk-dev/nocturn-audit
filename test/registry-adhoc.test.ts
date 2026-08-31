import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { projeDizinden, dizinGibiMi } from "../src/registry.js";

/*
  Bir guvenlik araci, uzerinde durdugun klasorde BIR KEZ calismalidir.
  Onceden `scan .` "targets.json not found" diyip KURULU PAKETIN icindeki
  bir yolu gosteriyordu -- kullanicinin olusturamayacagi bir dosya. Bu
  testler o yolun acik kalmasini guvenceye aliyor.
*/
describe("dizinden ad-hoc proje", () => {
  it("dizin gibi gorunen argumanlari taniyor", () => {
    for (const d of [".", "..", "./app", "../app", "/abs/yol", "~/kod"]) {
      expect(dizinGibiMi(d)).toBe(true);
    }
  });

  it("kayit defterindeki duz adi dizin sanmiyor", () => {
    for (const ad of ["toolcompare", "my-app", "gelecekfinans"]) {
      expect(dizinGibiMi(ad)).toBe(false);
    }
  });

  it("dizinden proje uretiyor: ad klasor adi, owned true, url yok", () => {
    const kok = mkdtempSync(join(tmpdir(), "na-"));
    mkdirSync(join(kok, "src"));
    writeFileSync(join(kok, "package.json"), JSON.stringify({ dependencies: { next: "15.0.0" } }));
    const p = projeDizinden(kok);
    expect(p.name).toBe(basename(kok));
    expect(p.path).toBe(kok);
    expect(p.owned).toBe(true);
    // url YOK: kimsenin bildirmedigi bir adrese canli istek atilmaz.
    expect(p.url).toBeUndefined();
    expect(p.stack.framework).toBe("next");
  });

  it("dizin degilse acikca hata veriyor", () => {
    expect(() => projeDizinden(join(tmpdir(), "na-yok-boyle-bir-yol"))).toThrow(/Not a directory/);
  });
});
