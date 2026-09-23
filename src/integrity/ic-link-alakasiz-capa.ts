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

/**
 * Başlık/anahtar kelimeden çapa çıkarımı. Satır sonu serbest: gerçek kodda
 * `article.title` ile `.split(` ayrı satırlarda durur.
 */
const BASLIKTAN_CAPA = /\b(title|baslik|başlık|keyword|anahtar)\b[\s\S]{0,120}?\.\s*split\s*\(/i;

/**
 * Çapa kapısı KELİME UZUNLUĞU: `filter((w) => w.length > 4)`.
 *
 * Kapı, KELİME dizisi üzerinde süzgeç olmak zorunda. Serbest bir `x.length > n`
 * aramak yanlış alarm üretir: `faq.length > 0`, `title.length < 30` gibi dizi ve
 * karakter denetimleri her SEO/JSX dosyasında geçer (ilk sürüm gelecekfinans'ta
 * 4 bulgunun 3'ünü böyle uydurmuştu).
 */
const UZUNLUK_KAPISI =
  /\.\s*(filter|some|every)\s*\(\s*\(?\s*(\w+)\s*\)?\s*=>[^\n]*\b\2\s*\.\s*length\s*(>=?|>)\s*\d+/;

/** Çapa kapısı ELLE YAZILMIŞ KELİME LİSTESİ: `GENERIC.has(w)`, `STOPWORDS.includes(w)`… */
const LISTE_KAPISI = /\b(\w*(GENERIC|JENERIK|STOP|DOLGU|BLACKLIST|EXCLUDE)\w*|isGenericAnchor|jenerikMi)\b\s*[.(]/i;

/**
 * DOĞRU KAPININ KANITI: çekimli fiil eki deseni ya da kapalı sınıf kelime kümesi.
 *
 * Jenerik kelime LİSTESİ bu kanıt değildir — 4 Eylül'de gelecekfinans'a tam
 * olarak bu liste eklendi ve arıza bir gün sonra listede olmayan kelimelerle
 * ("yalnızca", "devam") geri döndü. Liste sonludur, dil değildir.
 */
const YAPISAL_KANIT =
  /(ecek\|acak|ıyor\|iyor|mış\|miş|FUNCTION_WORDS|KAPALI_SINIF|isFiniteVerbForm|cekimliFiil|çekimliFiil|isContentWord|icerikKelimesi|içerikKelimesi|morpholog|lemma|zemberek)/i;

/**
 * KALICI MERKEZ LİSTESİ dönüşümlü kullanılabilir: kategori/veri merkezi sayfaları
 * her makale için zaten alakalıdır (aynı kategorinin kendisi), dolayısıyla
 * `hubs[i % hubs.length]` bu arıza değil — alakalı aday bulunamadığında düşülen
 * DOĞRU davranıştır. Konu seçimi yapılan yer makale havuzudur.
 */
const HUB_HAVUZU = /\b(hubs?|kategori|category|merkez|fallback|varsayilan|varsayılan|banner)\b/i;

/** Aday havuzundan SIRAYLA seçim: `pool[i % pool.length]`. */
const SIRAYLA_SECIM = /\[\s*\w+\s*%\s*\w+(\.\w+)*\s*\.\s*length\s*\]/;

/**
 * Konu örtüşmesi ölçüldüğüne dair kanıt. YEREL bağlamda aranır: dosyanın başka
 * bir fonksiyonunda "cluster" geçmesi, buradaki seçimin alakaya baktığını
 * göstermez. (İlk taslak dosya genelinde arıyordu ve gerçek arızalı dosyayı
 * kaçırdı: aynı dosyada alakasız bir `linkGuideCluster` fonksiyonu vardı.)
 */
const ALAKA_KANITI =
  /(relevance|relevans|alaka|similarit|benzerlik|overlap|ortusme|örtüşme|score|puan|embedding|cosine|tfidf)/i;

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

const REMEDIATION =
    "Çapa metnini kelime uzunluğu ya da kelime listesiyle değil YAPIYLA süzün: " +
    "kapalı sınıf kelimeler (bağlaç/zarf/edat — sayısı sabittir, listeyle " +
    "büyümez) ve çekimli fiil biçimleri (-ecek/-acak/-ıyor/-dı/-mış eki) çapa " +
    "olamaz; çapa en az bir içerik kelimesi taşımalı. Hedefi de konu örtüşmesi " +
    "ölçerek seçin (hedefin anahtar kelimesi metinde gerçekten geçiyor mu?); " +
    "alakalı aday yoksa bağlantıyı hiç kurmayın, kalıcı bir kategori/merkez " +
    "sayfasına düşün.";

export const icLinkAlakasizCapa: StaticRule = {
  id: "int-ic-link-alakasiz-capa",
  title: "Internal link anchor/target chosen without checking the topic",
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
      const capaCikarimi = BASLIKTAN_CAPA.test(kod);
      const yapisal = YAPISAL_KANIT.test(kod);

      // ── 1) Çapa metni: kapı yalnızca uzunluk ve/veya elle yazılmış liste mi?
      if (capaCikarimi && !yapisal) {
        const i = lines.findIndex(
          (satir) => UZUNLUK_KAPISI.test(satir) || LISTE_KAPISI.test(satir),
        );
        if (i >= 0) {
          const satir = lines[i] ?? "";
          const listeyle = LISTE_KAPISI.test(satir);
          findings.push({
            ruleId: this.id,
            title: this.title,
            owasp: this.owasp,
            severity: "medium",
            confidence: "likely",
            description:
              `${file}:${i + 1} — iç bağlantının ÇAPA METNİ ` +
              (listeyle
                ? "elle yazılmış bir jenerik kelime listesiyle"
                : "yalnızca kelime uzunluğuyla") +
              ` süzülüyor; kapalı sınıf kelime (bağlaç/zarf/edat) ya da çekimli fiil ` +
              `eki denetimi yok. Türkçede bu kapı "yalnızca" (8 harf), "hesaplanır" ` +
              `(10), "edecek" (6) gibi kelimeleri geçirir; hiçbiri bir sayfanın konusu ` +
              `değildir. Okur beklediği sayfayı bulamaz, arama motoru da çapayı hedefin ` +
              `konusu sanıp sayfayı yanlış sorguyla ilişkilendirir. Liste kapısı ` +
              `kalıcı çözüm değildir: her yeni haber fiilinde yetersiz kalır.`,
            evidence: [fileEvidence(file, i + 1, satir.trim().slice(0, 200))],
            remediation: REMEDIATION,
          });
        }
      }

      // ── 2) Hedef seçimi: alaka ölçülmeden sırayla mı doldurulıyor?
      for (let i = 0; i < lines.length; i++) {
        const satir = lines[i] ?? "";
        if (!SIRAYLA_SECIM.test(satir)) continue;
        if (HUB_HAVUZU.test(satir)) continue; // kalıcı merkez listesi: zaten alakalı
        // Yerel bağlam: seçimin YAPILDIĞI yerde alaka ölçülüyor mu?
        const baglam = lines.slice(Math.max(0, i - 12), i + 13).join("\n");
        if (ALAKA_KANITI.test(baglam)) continue;
        // Bağlantı kurulumu bu seçimin yakınında mı? Değilse başka bir modulo.
        if (!LINK_URETIMI.test(baglam)) continue;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "medium",
          confidence: "likely",
          description:
            `${file}:${i + 1} — bağlantı HEDEFİ aday havuzundan sırayla ` +
            `(\`% length\`) seçiliyor, konu örtüşmesi ölçülmüyor. Aynı kategoride ` +
            `olmak "ilgili" sayılıyor, o da yoksa havuzdaki ilk kayıt konuluyor: bir ` +
            `sigorta haberi altcoin haberine bağlanabilir. Üretici bunu yine "iç ` +
            `bağlantı eklendi" diye raporlar, arıza yalnızca yayında görülür.`,
          evidence: [fileEvidence(file, i + 1, satir.trim().slice(0, 200))],
          remediation: REMEDIATION,
        });
        break; // dosya başına tek hedef bulgusu
      }
    }
    return findings;
  },

};
