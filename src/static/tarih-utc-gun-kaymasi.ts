import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — Tarih-only değer `toISOString()` ile üretiliyor → GÜN/AY KAYMASI.
 *
 * `Date.prototype.toISOString()` her zaman UTC verir. Bir "gün" (YYYY-MM-DD) ya da
 * "ay" (YYYY-MM) değeri üretirken kullanıldığında, yerel saat dilimi UTC'den farklıysa
 * sonuç KAYAR. Bu, kodu okurken doğru görünen ve testlerin kaçırdığı bir hatadır:
 * ifade geçerlidir, sonucu yanlıştır.
 *
 * İKİ AYRI KAYMA:
 *
 * 1) YEREL PARSE + UTC ÇIKTI (kesin hata):
 *      const d = new Date(iso + "T00:00:00");   // YEREL gece yarısı
 *      d.setDate(d.getDate() + n);
 *      return d.toISOString().slice(0, 10);     // UTC'ye çevir
 *    UTC+X bölgelerinde sonuç HER ZAMAN bir gün geridir. UTC-X'te bir gün ileri.
 *
 * 2) UTC GÜNÜNÜ "BUGÜN" SAYMAK:
 *      const bugun = new Date().toISOString().slice(0, 10);
 *    UTC+3'te gece 00:00–03:00 arası bu değer DÜNÜ gösterir.
 *
 * GERÇEK VAKA (yanindapos, 2026-09-05 — canlı tıklama testinde bulundu, hiçbir
 * birim test görmemişti):
 *   - Rezervasyon takvimindeki 7 günlük şerit bugünden değil DÜNDEN başlıyordu ve
 *     dünün bütün saatleri "müsait" görünüyordu → müşteri geçmişe randevu alabiliyordu.
 *   - `nextMonthFirstISO` yerel ayın 1'ini üretip UTC'ye çeviriyordu → sonuç ÖNCEKİ
 *     AYIN SON GÜNÜ; abonelik yenileme tarihi bir ay yanlış çıkabiliyordu.
 *   - Aylık ciro grafiğinin ay anahtarı ayın 1'inde önceki aya düşüyordu → ETİKET
 *     eylül, VERİ ağustos.
 *   - Asıl sinsi kısım: yardımcı fonksiyon düzeltildikten SONRA bile ürün bozuktu,
 *     çünkü aynı fonksiyonun KOPYALARI üç ayrı dosyada yaşıyordu. Bu kural dosya
 *     bazında çalıştığı için kopyaları da tek tek yakalar.
 *
 * DOĞRU KULLANIMLAR (bulgu üretilmez):
 *   - `Date.UTC(...)` ile kasıtlı UTC aritmetiği,
 *   - `.toISOString()` tam zaman damgası olarak (createdAt vb.) — kesme yok,
 *   - `Intl.DateTimeFormat` ile bölge belirtilmiş biçimlendirme.
 */

const isJsTs = (f: string) =>
  /\.(js|ts|mjs|cjs|jsx|tsx)$/.test(f) && !/(\.test\.|\.spec\.|\.d\.ts$|__tests__|\/tests?\/)/.test(f);

// Tarih-only kesme: .slice(0, 10) → gün, .slice(0, 7) → ay.
const KESME = /toISOString\(\)\s*\.\s*slice\(\s*0\s*,\s*(10|7)\s*\)/;
// Kasıtlı UTC aritmetiği — bu bir hata değil.
const UTC_KASITLI = /Date\.UTC\s*\(/;
// Yerel gece yarısı üretimi ya da yerel alan mutasyonu.
const YEREL_URETIM = /(T00:00:00|\.setDate\s*\(|\.setMonth\s*\(|\.setFullYear\s*\(|new Date\s*\(\s*\w+\s*\.\s*getFullYear)/;
// Argümansız `new Date()` → "şu an", UTC gününe çevriliyor.
const SIMDI = /new Date\s*\(\s*\)/;

/**
 * Yorumları çıkar. Bu kuralın kendi açıklaması gibi metinlerde `toISOString()`
 * geçer; YORUMDAKİ bir örnek yüzünden bulgu üretmek aracın güvenilirliğini bitirir.
 * (Gerçek vaka: hatayı düzelten ekip, ne yaptığını yorumda anlatmıştı.)
 */
function yorumsuz(kod: string): string[] {
  return kod
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))  // satır sayısı korunur
    .split(/\r?\n/)
    .map((l) => l.replace(/\/\/.*$/, "").replace(/^\s*\*.*$/, ""));
}

export const tarihUtcGunKaymasi: StaticRule = {
  id: "a04-tarih-utc-gun-kaymasi",
  title: "Tarih/ay değeri toISOString() ile üretiliyor (saat dilimine göre gün kayar)",
  owasp: "A04:2021-Insecure Design",
  severity: "medium",
  kind: "static",
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files.filter(isJsTs)) {
      const raw = ctx.read(file);
      if (!raw || !raw.includes("toISOString")) continue;
      const lines = yorumsuz(raw);

      for (let i = 0; i < lines.length; i++) {
        const satir = lines[i] ?? "";
        if (!KESME.test(satir)) continue;
        if (UTC_KASITLI.test(satir)) continue;   // bilinçli UTC aritmetiği

        // Yakın bağlam: yerel üretim aynı ifadenin birkaç satır üstünde olabilir.
        const baglam = lines.slice(Math.max(0, i - 4), i + 1).join("\n");
        if (UTC_KASITLI.test(baglam)) continue;

        const ay = /slice\(\s*0\s*,\s*7\s*\)/.test(satir);
        const yerel = YEREL_URETIM.test(baglam);
        const simdi = SIMDI.test(satir);

        // Ne yerel üretim ne de "şu an" varsa: değer başka yerden gelmiş olabilir,
        // iddia edecek kadar bilgi yok. Sessiz kal — yanlış alarm üretme.
        if (!yerel && !simdi) continue;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "medium",
          confidence: yerel ? "certain" : "likely",
          description: yerel
            ? `${file}:${i + 1} — yerel bir Date üretilip (\`T00:00:00\` ya da ` +
              `\`setDate/setMonth\`) sonuç \`toISOString()\` ile UTC'ye çevriliyor ve ` +
              `${ay ? "AY" : "GÜN"} olarak kesiliyor. UTC+X bölgelerinde sonuç HER ZAMAN ` +
              `bir ${ay ? "ay" : "gün"} geri, UTC-X'te bir ${ay ? "ay" : "gün"} ileri çıkar. ` +
              `Kod geçerli görünür, sonucu yanlıştır; birim testler bunu genellikle kaçırır.`
            : `${file}:${i + 1} — "bugün" değeri \`new Date().toISOString()\` ile, yani ` +
              `UTC gününden üretiliyor. UTC+3'te gece 00:00–03:00 arasında bu değer DÜNÜ ` +
              `gösterir: o saatlerde oluşturulan kayıt yanlış güne yazılır, abonelik/deneme ` +
              `bitişi ve fatura tarihi bir gün kayabilir.`,
          evidence: [fileEvidence(file, i + 1, satir.trim().slice(0, 200))],
          remediation:
            "Tarih-only aritmetiğini saat diliminden bağımsız yapın: parçaları ayırıp " +
            "`Date.UTC(y, m-1, d + n)` ile hesaplayın ve sonucu `getUTCFullYear/Month/Date` " +
            "ile biçimlendirin. \"Bugün\" için işletmenin bölgesini sabitleyin: " +
            "`new Intl.DateTimeFormat(\"en-CA\", { timeZone: \"Europe/Istanbul\", ... })` " +
            "(en-CA zaten YYYY-MM-DD verir). Bu yardımcıları TEK bir modülde tutun ve " +
            "kopyalarını arayın — düzeltilmiş bir yardımcının kopyası sessizce bozuk kalır.",
        });
      }
    }
    return findings;
  },
};
