import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { makeCtx } from "./helpers.js";
import { icLinkAlakasizCapa } from "../src/integrity/ic-link-alakasiz-capa.js";

/**
 * KURALIN GERÇEK ARIZAYI YAKALADIĞININ KANITI.
 *
 * Kural, gelecekfinans.com'da 5 Eylül 2026'da canlı bulunan arızadan çıkarıldı.
 * Bir kuralın kendi vakasını yakalayamaması sessiz temiz rapor üretir; bu yüzden
 * gerçek dosyanın ARIZALI ve DÜZELTİLMİŞ sürümleri git'ten okunup karşılaştırılır.
 *
 * Depo bu makinede yoksa test atlanır — kural kendi birim testleriyle zaten
 * kapsanıyor, bu ek kanıt makineye bağlı.
 */

const REPO = `${process.env.HOME}/Desktop/Web Siteleri/gelecekfinans-site`;
const DOSYA = "lib/bot/linker.ts";
const DUZELTME_COMMIT = "4ebcb59"; // "iç linkleme: bağlaç/fiil çapaları ... engellendi"

const gitShow = (ref: string): string | null => {
  try {
    return execFileSync("git", ["show", `${ref}:${DOSYA}`], {
      cwd: REPO,
      encoding: "utf-8",
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch {
    return null;
  }
};

const varMi = existsSync(REPO);

describe.skipIf(!varMi)("int — kural gerçek gelecekfinans arızasını yakalar", () => {
  it("ARIZALI sürüm (düzeltmeden önce) bulgu üretir", () => {
    const kod = gitShow(`${DUZELTME_COMMIT}~1`);
    if (kod === null) return; // commit bu kopyada yok
    const f = icLinkAlakasizCapa.run(makeCtx({ [DOSYA]: kod }));
    expect(f.length).toBeGreaterThan(0);
  });

  it("DÜZELTİLMİŞ sürüm temiz kalır (yanlış alarm yok)", () => {
    const kod = gitShow(DUZELTME_COMMIT);
    if (kod === null) return;
    const f = icLinkAlakasizCapa.run(makeCtx({ [DOSYA]: kod }));
    expect(f).toEqual([]);
  });
});
