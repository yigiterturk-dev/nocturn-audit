/**
 * SECURITY-GATE HELPER KEŞFİ — auth-helpers'ın genelleşmiş kardeşi.
 *
 * Sorun: güvenlik kapıları her projede FARKLI ŞEKİLDE yazılıyor. Webhook
 * doğrulaması kiminde `verifySnsSignature(...)`, kiminde `isWebhookAuthorized(...)`,
 * kiminde düz `checkToken(req)`. Sabit desen listesi bunları tek tek tanımak
 * zorunda — her yeni proje yeni bir isim getirdi ve kural ya sessiz kaldı ya da
 * yanlış pozitif üretti. (Gerçek vaka: bir e-ticaret CRM projesi'un isWebhookAuthorized'ı —
 * fail-closed secret kontrolü, desen listesine sonradan eklenmişti.)
 *
 * Çözüm auth-helpers ile aynı: **fonksiyonun adına değil GÖVDESİNE bak.**
 * Gövdesi sırrı okuyup karşılaştıran/ HMAC kuran her fonksiyon = doğrulama
 * kapısı. İki geçiş: önce doğrudanlar, sonra onları çağıran sarmalayıcılar.
 */
import type { StaticContext } from "./rule.js";

/** Gövdede doğrulama sinyali: sır/token okuma + karşılaştırma imzası. */
const DOGRULAMA_SINYALI =
  /(createHmac|timingSafeEqual|crypto\.verify|jose|jwt\.verify|verifySignature|verifySns|\.compare\(|===\s*|process\.env\.\w*(SECRET|TOKEN|KEY)|headers\.get\s*\(\s*['"][^"']*(signature|secret|token)[^"']*['"])/i;

const DOGRULAMA_ADI =
  /^(is|check|verify|validate|assert|ensure|authorize|has|doğrula|kontrol)\w*(authorized|signature|verify|hmac|token|secret|webhook|auth|kapı|yetki)\w*$/i;

const TANIM =
  /export\s+(?:async\s+)?function\s+(\w+)|(?:export\s+)?(?:async\s+)?function\s+(\w+)|(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(|(?:export\s+)?const\s+(\w+)\s*=\s*\w+\s*\(/g;

export function collectDogrulamaHelperlari(ctx: StaticContext): Set<string> {
  const dogrudan = new Set<string>();
  const govdeler = new Map<string, string>();

  for (const file of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file)) continue;
    if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
    const content = ctx.read(file);
    if (!content) continue;

    TANIM.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TANIM.exec(content)) !== null) {
      const ad = m[1] || m[2] || m[3] || m[4];
      if (!ad || !DOGRULAMA_ADI.test(ad)) continue;
      const body = content.slice(m.index, m.index + 1200);
      govdeler.set(ad, body);
      if (DOGRULAMA_SINYALI.test(body)) dogrudan.add(ad);
    }
  }

  // Sarmalayıcılar: bilinen bir kapıyı çağıran kapı da kapıdır (3 tur).
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
