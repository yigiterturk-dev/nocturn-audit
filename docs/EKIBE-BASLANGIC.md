# Başlangıç (5 dakika)

```bash
npm install
npm run build
```

## 1. Hangi projeler taranacak?

`targets.json` — kopyala, kendi projelerinle doldur:

```json
{
  "projects": [
    {
      "name": "musteri-paneli",
      "path": "~/is/musteri-paneli",
      "url": "https://panel.ornek.com",
      "owned": true,
      "stack": { "framework": "next", "db": "supabase", "auth": "clerk" }
    }
  ]
}
```

- `path` — proje kökü (`~` çalışır)
- `url` — canlı adres. **`owned: true` olmadan canlı test YAPILMAZ.**
  Bu bir güvenlik kapısıdır: yalnızca sahibi olduğun adrese istek atılır.
- `stack` — boş bırakılabilir, `package.json`'dan keşfedilir

> ⚠️ Yol yanlışsa araç sessizce "temiz" demez, "proje yolu bulunamadı" der.
> Yine de kontrol et: taranmayan proje, temiz proje değildir.

## 2. Tara

```bash
npm run denetim              # hepsi (statik + canlı + bağımlılık)
npm run denetim musteri-paneli   # tek proje
npm run denetim:hizli        # yalnızca kod okuma, ağa dokunmaz
```

Rapor üç biçimde: terminalde özet, `report/YYYY-MM-DD.html` (paylaşılabilir),
`report/YYYY-MM-DD.json` (araç okusun diye).

**Raporu nasıl okuyacağın ayrı bir belge:** [RAPOR-NASIL-OKUNUR.md](./RAPOR-NASIL-OKUNUR.md)

## 3. Değişiklik yaptıktan sonra

```bash
npm run fark -- report/dun.json report/bugun.json
```

Kaybolan bulgu gerçekten mi düzeldi, yoksa sadece görünmez mi oldu — onu söyler.

## Kurala dokunacaksan

```bash
npm run dogrula
```

Üç şeyi birden çalıştırır ve üçü de geçmeden kural değişikliği kabul edilmez:

1. **527 test** — her kuralın BAD (yakalamalı) ve CLEAN (yakalamamalı) fikstürü
2. **canary** — `test/canary/` kasten açık bırakılmış bir proje. Kural fazla
   sıkılırsa buradaki 18 açıktan biri kaçar ve test kırılır.
3. **isabet kapısı** — etiketli korpusta elenmiş bir yanlış pozitif geri
   gelirse ya da doğrulanmış bir bulgu kaybolursa `exit 1`.

### Yeni kural yazacaksan: `npm run yeni-kural`

```bash
npm run yeni-kural -- a04-ornek-kural     # ya da int-ornek-kural
```

Üç dosya üretir ve registry'ye kaydeder:
- kural dosyası (`gerektirir: []` beyanıyla, TODO'lu)
- test dosyası (BAD + CLEAN fikstür iskeletiyle)
- `src/rules.ts` kaydı — elle eklemeyi unutmak, kuralın **sessizce hiç
  çalışmaması** demektir. Sessiz kural, olmayan kuraldan kötüdür: var sanılır.

**Üretilen testler BAŞTA KIRMIZIDIR.** Doldurmadan kural yeşile dönmez. Bu
kasıtlı: aşağıdaki üç şart belgede değil, üretilen dosyalarda duruyor.

### Yeni kural yazacaksan üç şart

1. **BAD fikstürü olmayan kural girmez.** Yakaladığını göster.
2. **CLEAN fikstürü de yaz.** Neyi yakalamayacağını göster — asıl zor kısım bu.
3. **`gerektirir` beyan et.** Kuralın neye ihtiyacı var (`git`, `sql`, `js`,
   `canli`…). Boş dizi geçerli bir beyandır ("ön koşulum yok"). Beyan
   etmezsen test kırılır — çünkü ön koşulu karşılanmayan bir kuralın `[]`
   dönmesi "temiz" sanılır ve bu, aracın yapabileceği en tehlikeli hatadır.

### Kural sıktığında

Canary'ye o açığın **gerçekçi** bir örneğini ekle. Fikstür senin hayal ettiğin
açıktır; canary sahada nasıl göründüğüdür. İkisi aynı değil — canary kurulduğu
gün, bütün fikstürleri `req.json()` ile yazılmış bir kuralın form gövdesini
artık görmediği ortaya çıktı.
