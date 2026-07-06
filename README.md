# nocturn-audit

Kendi projelerini (Next.js / Vite + Supabase / Neon / Clerk) **pentestçi metodolojisiyle**
denetleyen tek bir CLI. OWASP Top 10 (2021) eşlemeli. **Sadece tespit + raporlama** —
exploit yok, DoS yok, evasion yok.

Canlı HTTP problar **yalnızca** `targets.json`'da `owned: true` işaretli, senin sahibi
olduğun URL'lere yapılır. Düşük yoğunluklu, yıkıcı değil.

## Kurulum

```bash
npm install
npm run build
```

Node.js 20+ gerekir (yerleşik `fetch` kullanılıyor). `npx nocturn-audit` için `bin` tanımlı.

## targets.json

`targets.example.json`'u kopyala, kendi projelerinle doldur:

```json
{
  "projects": [
    {
      "name": "emlakakli",
      "path": "~/Desktop/Web Siteleri/emlakakli",
      "url": "https://emlakakli.vercel.app",
      "owned": true,
      "stack": { "framework": "next", "db": "supabase", "auth": "clerk" }
    }
  ]
}
```

- `path` — proje kök dizini (`~` desteklenir).
- `url` — canlı adres (opsiyonel; yoksa canlı test atlanır).
- `owned` — **canlı test için `true` şart.** `false`/eksikse sadece statik tarama çalışır.
- `stack` — boş bırakılabilir; `package.json`'dan otomatik keşfedilir.

Repodaki örnek `targets.json` güvenlik için hepsini `owned: false` bırakır — canlı prob
istediğinde ilgili projeyi `owned: true` yap.

## Kullanım

```bash
npx nocturn-audit scan               # tüm projeler (statik + canlı + deps)
npx nocturn-audit scan emlakakli     # tek proje
npx nocturn-audit scan --static      # sadece kod taraması (canlıya dokunma, deps de atlanır)
npx nocturn-audit scan --live-only   # sadece canlı HTTP problar
npx nocturn-audit scan --no-deps     # npm audit adımını atla
npx nocturn-audit list               # kayıtlı projeleri göster
npx nocturn-audit rules              # aktif kural setini göster
```

Ek bayraklar: `-t <path>` (özel targets.json), `-v` (tüm bulguları terminalde göster).

## Rapor

- **Terminal** — proje bazında renkli özet (C/H/M/L/I + risk skoru).
- **`report/<tarih>.html`** — proje proje, OWASP kategorili; her bulguda kanıt
  (dosya:satır ya da HTTP istek/yanıt), severity, düzeltme önerisi.
- **`report/<tarih>.json`** — makine okunur (CI'a bağlanabilir).
- **Çıkış kodu** — kritik bulgu varsa `exit 1` → deploy öncesi gate olarak kullan.

## Kapsam (OWASP Top 10 2021)

A01 Broken Access Control · A02 Cryptographic Failures · A03 Injection ·
A04 Insecure Design · A05 Security Misconfiguration · A06 Vulnerable Components (npm audit) ·
A07 Auth Failures · A08 Data Integrity (webhook imza) · A09 Logging · A10 SSRF.

Kural listesi: `npx nocturn-audit rules`.

## Mimari

Her kural tek amaçlı bir dosya (`Rule` arayüzü: `{ id, title, owasp, severity, run(ctx) }`).
Yeni açık türü = yeni dosya, motora dokunmadan.

```
src/
  cli.ts            komutlar
  registry.ts       targets.json + stack otomatik keşif
  core/             finding, severity, engine, rule (arayüz + bağlamlar)
  static/           kod tarayıcı kuralları (fast-glob + regex/heuristik)
  live/             canlı HTTP prob kuralları (owned:true şart)
  deps/             npm audit sarmalayıcı
  report/           html, json, terminal
test/               her kural için fixture'lı vitest testi
```

## Test

```bash
npm test
```

Her detektör hem bilinçli-açıklı fixture'da tetiklenir hem de temiz kodda
false-positive üretmediği doğrulanır.

## Sınırlar (YAGNI)

Başkasına ait hedefe test yok. Yıkıcı/DoS/fuzzing yükü yok. Otomatik exploit/kalıcı erişim
yok. Detection evasion yok. Araç yalnızca **tespit + raporlama** yapar; bulguları sen
değerlendirirsin (özellikle "olası" işaretli statik/canlı bulguları manuel doğrula).
