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
 * kapısı. Motor core/kesif.ts'te; bu dosya doğrulama uzmanlığı.
 */
import type { StaticContext } from "./rule.js";
import { collectHelperlar } from "./kesif.js";

/** Gövdede doğrulama sinyali: sır/token okuma + karşılaştırma imzası. */
const DOGRULAMA_SINYALI =
  /(createHmac|timingSafeEqual|crypto\.verify|jose|jwt\.verify|verifySignature|verifySns|\.compare\(|===\s*|process\.env\.\w*(SECRET|TOKEN|KEY)|headers\.get\s*\(\s*['"][^"']*(signature|secret|token)[^"']*['"])/i;

const DOGRULAMA_ADI =
  /^(is|check|verify|validate|assert|ensure|authorize|has|doğrula|kontrol)\w*(authorized|signature|verify|hmac|token|secret|webhook|auth|kapı|yetki)\w*$/i;

const SPEC = { ad: DOGRULAMA_ADI, sinyal: DOGRULAMA_SINYALI } as const;

export function collectDogrulamaHelperlari(ctx: StaticContext): Set<string> {
  return collectHelperlar(ctx, SPEC);
}
