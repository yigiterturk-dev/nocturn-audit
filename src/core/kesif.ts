import type { StaticContext } from "./rule.js";

/**
 * GÖVDE-SİNYALLİ HELPER KEŞFİ — ortak çekirdek.
 *
 * auth-helpers ve gate-helpers aynı motorun iki kopyasıydı: TANIM deseni,
 * iki geçişli sarmalayıcı toplama, 1200 karakterlik gövde penceresi — birebir
 * aynı. Her yeni keşif türü (yetki, webhook, yapılandırma) kopya üretiyordu.
 * Bu dosya motoru bir kez yazar; uzmanlık yalnızca İKİ regexp'tir:
 *
 *   ad     → ucuz ön süzgeç (isim kapısı — keşfe düşecek adayları daraltır)
 *   sinyal → karar (gövde bu işi GERÇEKTEN yapıyor mu)
 *
 * Kural şu: isme göre karar YOK, gövdeye göre var. İsim kapısı yalnızca
 * performans içindir; son söz daima sinyalin.
 */

export interface KesifSpec {
  /** İsim kapısı — aday helper adları bu desene uymalı. */
  ad: RegExp;
  /** Gövde sinyali — helper'ın gövdesi (ilk 1200 karakter) bunu içermeli. */
  sinyal: RegExp;
}

// `export const getUserRole = cache(async () => ...)` sarmalı keşfe düşmüyordu
// (bir e-ticaret CRM projesi, 12 sahte HIGH). Sarmalayıcı adı bilinçli olarak serbest.
const TANIM =
  /export\s+(?:async\s+)?function\s+(\w+)|(?:export\s+)?(?:async\s+)?function\s+(\w+)|(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(|(?:export\s+)?const\s+(\w+)\s*=\s*\w+\s*\(/g;

const KOD_DOSYASI = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const HARIC = /(test|spec|__tests__|fixtures?)/;

/**
 * Projenin KENDİ helper'larını keşfeder: önce gövdesi sinyal taşıyanlar,
 * sonra onları çağıran sarmalayıcılar (3 tur — zincir derinliği pratikte 3'ü
 * geçmez). Tek geçiş her sarmalanmış helper'ı kaçırırdı; gerçek projelerde
 * sarmalama kural, istisna değil.
 */
export function collectHelperlar(ctx: StaticContext, spec: KesifSpec): Set<string> {
  const dogrudan = new Set<string>();
  const govdeler = new Map<string, string>();

  for (const file of ctx.files) {
    if (!KOD_DOSYASI.test(file) || HARIC.test(file)) continue;
    const content = ctx.read(file);
    if (!content) continue;

    TANIM.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TANIM.exec(content)) !== null) {
      const ad = m[1] || m[2] || m[3] || m[4];
      if (!ad || !spec.ad.test(ad)) continue;
      const body = content.slice(m.index, m.index + 1200);
      govdeler.set(ad, body);
      if (spec.sinyal.test(body)) dogrudan.add(ad);
    }
  }

  const hepsi = new Set(dogrudan);
  for (let tur = 0; tur < 3; tur += 1) {
    for (const [ad, body] of govdeler) {
      if (hepsi.has(ad)) continue;
      for (const bilinen of hepsi) {
        if (new RegExp(`\\b${bilinen}\\s*\\(`).test(body)) {
          hepsi.add(ad);
          break;
        }
      }
    }
  }
  return hepsi;
}

/** Verilen içerik, keşfedilen helper'lardan birini çağırıyor mu? */
export function callsHelper(content: string, helpers: Set<string>): boolean {
  for (const ad of helpers) {
    if (new RegExp(`\\b${ad}\\s*\\(`).test(content)) return true;
  }
  return false;
}
