# Raporu nasıl okurum

Bu araç bilerek "kaç bulgu buldum" yarışı yapmaz. Bir bulgunun **ne kadar
kesin** olduğu, **kaç tane** olduğundan önemlidir. Raporu okurken sıra şu:

## 1. Önce "ÖLÇÜLEMEDİ" satırlarına bak

```
⃠ ölçülemedi (2 kural): SQL şema/migration dosyası yok — a01-missing-rls, a04-fk-cascade-off
```

Bu satır raporun **en dürüst** kısmıdır: aracın bakamadığı yeri söyler.
Bulgu yokluğu iki anlama gelebilirdi — "baktım, temiz" ya da "bakamadım".
Araç artık ikisini karıştırmıyor. Buradaki kurallar hakkında **hiçbir şey
bilmiyorsun**; "temiz" sanma.

## 2. KESİN / OLASI ayrımı

| Etiket | Anlamı | Ne yapmalı |
|---|---|---|
| **KESİN** | Kanıt deterministik. Sır git geçmişinde ya var ya yok. | Doğrudan işlem yap |
| **OLASI** | Desen eşleşti, bağlam sezgisel. | Önce kodu aç, oku |

`KESİN yüksek` sayısı sıfırdan büyükse gün oradan başlar. `OLASI` bulgular
bir liste değil, bir **soru listesidir**.

## 3. Seviyeler ne demek

- **critical / high** — sömürülebilir, öncelikli
- **medium** — gerçek zayıflık ama sömürüsü koşullu
- **low** — doğru tespit, riski düşük ya da başka katman kapatıyor
  (ör. CSRF token'ı yok ama SameSite + JSON gövde koruyor)
- **info** — bulgu değil **envanter**. "Şurada kimliksiz okuma var, bilerek mi?"
  gibi. Risk skoruna girmez.

## 4. Risk skoru bir hedef değildir

Skor kaba bir toplamdır; kıyaslamak için değil, **kendi geçmişinle**
karşılaştırmak içindir. Skorun düşmesi tek başına iyi haber değildir —
susturulmuş bir kural da skoru düşürür. Doğru soru: *"hangi bulgu kapandı ve
kapandığını nereden biliyorum?"*

## 5. Bulgu kaybolduğunda: `npm run fark`

```bash
npm run fark -- report/2026-08-24.json report/2026-08-25.json
```

Kaybolan her bulgu için tek soruyu sorar:

- bulgu gitti **+ dosya değişti** → düzeltme olabilir ✅
- bulgu gitti **+ dosya aynı** → ⚠️ **düzeltme sayılmaz.** Değişen kod değil,
  kural. Açık büyük olasılıkla yerinde duruyor. (Komut `exit 1` verir.)

Bu, gerçek bir olaydan doğdu: bir SSRF açığına fren eklendi, sonraki koşuda
bulgu yoktu, "düzeldi" sanıldı — oysa kuralın satır penceresi kaymıştı, açık
yerinde duruyordu.

## 6. Araç kendi isabetini biliyor

```bash
npm run precision
```

Etiketli korpusa karşı kural bazında isabet oranı verir. Bir kural %0'sa,
o kuralın çıktısına **güvenme** — düzeltilmesi gereken kuraldır, kod değil.

## Sık sorulanlar

**"Bulgu sayısı arttı, kötüye mi gidiyoruz?"**
Şart değil. Kural sıkıldığında görünürlük artabilir. `npm run fark` ile
karşılaştır: yeni bulgular gerçekten yeni mi, yoksa artık görülebiliyor mu?

**"Bu bulgu bizde tasarım gereği, her koşuda çıkıyor."**
Kanıtla birlikte `corpus/labels.json` içinde `fp` işaretle ve **nedenini yaz**.
Bir daha isabeti düşürmez ve gerekçe kalıcı olur.

**"Kural bizim mimarimize uymuyor."**
Kuralı kapatmadan önce `gerektirir` beyanına bak: belki ön koşulu zaten
karşılanmıyordur ve "ölçülemedi" demesi gerekirken bulgu üretiyordur.
