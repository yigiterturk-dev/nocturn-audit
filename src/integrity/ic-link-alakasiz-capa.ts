import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * Otomatik iç bağlantı üreticisi, ÇAPA METNİNİ ve HEDEFİ konuya bakmadan seçiyor.
 *
 * İçerik üreten her sitede aynı kod yazılır: yayımlanmış makaleleri getir,
 * başlıklarından bir kelime yakala, metinde geçtiği yere link koy. İki yerde
 * sessizce bozulur ve ikisi de "2 iç bağlantı eklendi" diye RAPORLANIR:
 *
 * 1) ÇAPA, KELİME UZUNLUĞUNA GÖRE seçiliyor:
 *      title.split(/\s+/).filter((w) => w.length > 4)
 *    Türkçede bu filtre bağlaçları ve çekimli fiilleri geçirir: "yalnızca" (8),
 *    "hesaplanır" (10), "edecek" (6). Hiçbiri bir sayfanın KONUSU değildir.
 *
 * 2) HEDEF, SIRAYLA seçiliyor:
 *      const target = pool[index % pool.length];
 *    Aynı kategoride olmak "ilgili" sayılır, o da yoksa havuzdaki ilk makale
 *    konur. Konu örtüşmesi hiç ölçülmez.
 *
 * GERÇEK VAKA (gelecekfinans.com — 4 ve 5 Eylül 2026, ikisi de CANLI yakalandı):
 *   - "Enflasyon nedir nasıl hesaplanır" yazısının giriş cümlesindeki "nasıl"
 *     kelimesi, ilgisiz iki makaleye bağlanmıştı ("nasıl" 5 harf, eşiği geçiyor).
 *   - Bir gün sonra aynı arıza yeni kelimelerle döndü: DASK poliçesi haberinde
 *     "yalnızca" bir altcoin haberine, "devam edecek" bir e-ihracat haberine
 *     bağlanmıştı. Sebep, ilk düzeltmenin JENERİK KELİME LİSTESİ olmasıydı;
 *     liste her yeni haber fiilinde yetersiz kalıyordu.
 *
 * ZARARI İKİ YÖNLÜ: okur tıkladığında beklediği sayfayı bulamaz; arama motoru
 * çapa metnini hedef sayfanın konusu sanar, yani sayfayı YANLIŞ sorguyla
 * ilişkilendirir. Bağlantının bütün değeri çapa metnindedir — anlamsız çapa
 * değersiz değil, ZARARLIDIR. Hiç bağlantı vermemek bundan iyidir.
 *
 * DOĞRU KURULUM (bulgu üretilmez): çapa listesi kapalı sınıf kelimeleri
 * (bağlaç/zarf/edat) ve çekimli fiil biçimlerini eler, hedef ise konu örtüşmesi
 * ölçülerek seçilir; alakalı aday yoksa kalıcı bir kategori/merkez sayfasına
 * düşülür.
 */

const isJsTs = (f: string) =>
  /\.(js|ts|mjs|cjs|jsx|tsx)$/.test(f) &&
  !/(\.test\.|\.spec\.|\.d\.ts$|__tests__|\/tests?\/)/.test(f);

/** Dosya gerçekten iç bağlantı mı üretiyor? `href="/..."` ya da <a href kurulumu. */
const LINK_URETIMI = /(<a\s+href=|href=["'`]\/|href=\{?["'`]?\/|createLink|internalLink|iclink)/i;

/** Başlık/anahtar kelimeden çapa çıkarımı. */
const BASLIKTAN_CAPA = /\b(title|baslik|başlık|keyword|anahtar)\b[^\n]{0,80}\.\s*split\s*\(/i;

/** Tek ölçüt kelime uzunluğu: `w.length > 4`, `word.length >= 5`… */
const UZUNLUK_FILTRESI = /\.\s*(filter|some|every)\s*\(\s*\(?\s*(\w+)\s*\)?\s*=>[^\n)]*\2\s*\.\s*length\s*(>=?|>)\s*\d/;

/** Aday havuzundan SIRAYLA seçim: `pool[i % pool.length]`. */
const SIRAYLA_SECIM = /\[\s*\w+\s*%\s*\w+(\.\w+)*\s*\.\s*length\s*\]/;

/**
 * Konu örtüşmesi ölçüldüğüne dair kanıt. Herhangi biri varsa hedef/çapa seçimi
 * alakaya dayanıyor demektir; bu kural sessiz kalır.
 */
const ALAKA_KANITI =
  /(relevance|relevans|alaka|similarit|benzerlik|overlap|ortusme|örtüşme|score|puan|cluster|küme|kume|embedding|cosine|tfidf|isContentWord|icerikKelimesi|içerikKelimesi)/i;

/**
 * Yorumları çıkar: bu kuralın kendi açıklaması gibi metinler örnek kod taşır,
 * yorumdaki bir örnek yüzünden bulgu üretmek aracın güvenilirliğini bitirir.
 */
function yorumsuz(kod: string): string[] {
  return kod
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")) // satır sayısı korunur
    .split(/\r?\n/)
    .map((l) => l.replace(/\/\/.*$/, "").replace(/^\s*\*.*$/, ""));
}

export const icLinkAlakasizCapa: StaticRule = {
  id: "int-ic-link-alakasiz-capa",
  title: "Otomatik iç bağlantı çapası/hedefi konuya bakmadan seçiliyor",
  owasp: "A04:2021-Insecure Design",
  severity: "medium",
  kind: "static",
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files.filter(isJsTs)) {
      const raw = ctx.read(file);
      if (!raw) continue;
      if (!LINK_URETIMI.test(raw)) continue;

      const lines = yorumsuz(raw);
      const kod = lines.join("\n");
      if (ALAKA_KANITI.test(kod)) continue; // alaka ölçülüyor: bu arıza değil

      for (let i = 0; i < lines.length; i++) {
        const satir = lines[i] ?? "";

        const uzunluk = UZUNLUK_FILTRESI.test(satir);
        const sirayla = SIRAYLA_SECIM.test(satir);
        if (!uzunluk && !sirayla) continue;

        // Uzunluk filtresi tek başına masumdur (kelime sayma, kısaltma ayıklama).
        // Bulgu, filtrenin ÇAPA çıkarımı bağlamında durmasını gerektirir.
        const baglam = lines.slice(Math.max(0, i - 6), i + 7).join("\n");
        if (uzunluk && !BASLIKTAN_CAPA.test(baglam)) continue;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "medium",
          confidence: "likely",
          description: uzunluk
            ? `${file}:${i + 1} — iç bağlantının ÇAPA METNİ yalnızca kelime uzunluğuna ` +
              `göre seçiliyor. Türkçede bu filtre bağlaç ve çekimli fiilleri geçirir ` +
              `("yalnızca" 8, "hesaplanır" 10, "edecek" 6 harf); hiçbiri bir sayfanın ` +
              `konusu değildir. Okur beklediği sayfayı bulamaz, arama motoru da çapayı ` +
              `hedefin konusu sanıp sayfayı yanlış sorguyla ilişkilendirir.`
            : `${file}:${i + 1} — bağlantı HEDEFİ aday havuzundan sırayla ` +
              `(\`% length\`) seçiliyor, konu örtüşmesi ölçülmüyor. Aynı kategoride ` +
              `olmak "ilgili" sayılıyor, o da yoksa havuzdaki ilk makale konuluyor: ` +
              `bir sigorta haberi altcoin haberine bağlanabilir. Üretici bunu yine ` +
              `"iç bağlantı eklendi" diye raporlar, arıza yalnızca yayında görülür.`,
          evidence: [fileEvidence(file, i + 1, satir.trim().slice(0, 200))],
          remediation:
            "Çapa metnini kelime uzunluğuyla değil YAPIYLA süzün: kapalı sınıf " +
            "kelimeler (bağlaç/zarf/edat — sayısı sabittir, listeyle büyümez) ve " +
            "çekimli fiil biçimleri (-ecek/-acak/-ıyor/-dı/-mış eki) çapa olamaz; " +
            "çapa en az bir içerik kelimesi taşımalı. Hedefi de konu örtüşmesi " +
            "ölçerek seçin (hedefin anahtar kelimesi metinde gerçekten geçiyor mu?); " +
            "alakalı aday yoksa bağlantıyı hiç kurmayın, kalıcı bir kategori/merkez " +
            "sayfasına düşün. Jenerik kelime LİSTESİ çözüm değildir: her yeni haber " +
            "fiilinde yetersiz kalır (gelecekfinans'ta arıza bir gün sonra yeni " +
            "kelimelerle geri döndü).",
        });
        break; // dosya başına tek bulgu: aynı üreticiyi tekrar tekrar bildirmeyelim
      }
    }
    return findings;
  },
};
