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
npx nocturn-audit standards          # Nocturn Standartları kontrol listesini göster
npx nocturn-audit standards <proje>  # standart profili çalıştır (rapor dosyası YAZMAZ)
```

Ek bayraklar: `-t <path>` (özel targets.json), `-v` (tüm bulguları terminalde göster),
`--no-standards` (scan sırasında standart profilini atla).

## Nocturn Standartları profili

OWASP kurallarından ayrı, "bu proje benim güvenlik + hız standartlarıma uyuyor mu"
sorusuna cevap veren checklist profili. Her `scan` (statik içeren) çalışmasında
otomatik koşar ve JSON rapora proje başına `standards` bloğu ekler
(OWASP bulgu sayımlarına ve risk skoruna DAHİL DEĞİLDİR).

- **Güvenlik** (kaynak: feedback_security): rate limit altyapısı, API auth guard,
  .env koruması (gitignore + commit), gömülü secret, güvenlik header'ları
  (next.config/vercel.json/middleware), Supabase RLS izi, input validation.
- **Hız** (kaynak: feedback_hiz_standardi / crm-v2 1.47s→0.26s vakası): Vercel
  bölge sabitleme, sayfa başına ardışık await zinciri (sezgisel), loading.tsx
  iskeletleri, `select *` daraltma.

Her kontrol **her zaman** bir sonuç üretir: `gecti` / `kaldi` / `manuel`
(sezgisel sinyal — elle doğrula, skoru DÜŞÜRMEZ) / `uygulanamaz`. Skor 0-100
(yüksek = iyi): kaldı-kritik −25, kaldı-uyarı −10, kaldı-bilgi −3.
Kesin olmayan sezgiseller (auth guard, await zinciri, RLS) asla "kaldı" olarak
işaretlenmez — yanlış pozitif skora yansımaz.

`standards <proje>` komutu rapor dosyası yazmaz (günlük güvenlik raporunun
üzerine yazıp konsol geçmişini kirletmemek için); kritik "kaldı" varsa `exit 1`.

## Rapor

- **Terminal** — proje bazında renkli özet (C/H/M/L/I + risk skoru).
- **`report/<tarih>.html`** — proje proje, OWASP kategorili; her bulguda kanıt
  (dosya:satır ya da HTTP istek/yanıt), severity, düzeltme önerisi.
- **`report/<tarih>.json`** — makine okunur (CI'a bağlanabilir).
- **Çıkış kodu** — kritik bulgu varsa `exit 1` → deploy öncesi gate olarak kullan.

## Kapsam (OWASP Top 10 2021)

A01 Broken Access Control · A02 Cryptographic Failures · A03 Injection ·
A04 Insecure Design · A05 Security Misconfiguration · A06 Vulnerable Components (npm audit) ·
A07 Auth Failures · A08 Data Integrity · A09 Logging · A10 SSRF.

Kural listesi: `npx nocturn-audit rules` (şu an 36 kural).

### Operasyonel / sağlık modülleri (yeni)

Solo geliştiricinin ~44 projeyi otomatik gözetmesi için eklenen 4 modül. Kalibrasyon
disiplini korunur: yalnızca gerçekten kesin olanlar `kesin`/yüksek, sezgiseller
`olası`/düşük.

- **A06 — Eski / deprecated bağımlılıklar** (`a06-outdated-deps`, deps): `a06-npm-audit`'i
  TAMAMLAR (çakışmaz). Bilinen deprecated paketler (request, node-sass, tslint, moment …,
  çevrimdışı → low/olası) ve `npm outdated --json` ile **≥ 2 major geride** kalan paketler
  (medium/olası). 1 major gerisi gürültü sayılıp elenir. `node_modules` yoksa outdated adımı
  atlanır (registry'ye gitmez).
- **A05 — Canlı SSL / domain sağlığı** (`a05-live-ssl-domain`, live, owned-gated): TLS
  sertifika **son kullanma** (< 7 gün veya süresi geçmiş = critical, < 30 gün = high — hepsi
  `kesin`), DNS çözümlemesi (olası), HTTP→HTTPS yönlendirmesi (olası) ve yönlendirme zinciri
  uzunluğu. Yıkıcı değil: tek TLS el sıkışması + birkaç HEAD/GET.
- **A05 — Build / yapılandırma sağlığı** (`a05-build-config-health`, static): kodda kullanılan
  ama `.env.example`/`.env*`'de tanımsız env değişkenleri ("env değişkeni kodda kullanılıyor ama
  .env.example'da tanımsız"), TS `strict` kapalı (info), next/vite'ta `build` script yokluğu
  (low) ve çözülemeyen relative import (best-effort, tavanlı, low). Hepsi düşük/olası;
  `tsc`/build ÇALIŞTIRILMAZ.
- **A05 — Canlı açıkta hassas dosya** (`a05-live-exposed-secrets`, live, owned-gated):
  `a05-live-exposed-files`'ı (.env, .git) TAMAMLAR. `.env.local`/`.env.production`/`.env.bak`
  (critical/kesin), DB dump/yedek `*.sql` (high), sır içeren `config.json` (high), açıkta
  `.js.map` kaynak haritası (medium). SPA 200-catch-all'a karşı her hedefte içerik imzası
  doğrulanır; iyi huylu public `config.json` elenir.

### Elite kurallar (yeni)

- **A02 — Hassas alan şifresiz saklanıyor** (`a02-sensitive-data-plaintext`): Prisma/Drizzle/SQL
  şema + migration'larda TC kimlik, SSN, pasaport, kart/CVV, IBAN, sağlık, OAuth/API token gibi
  alanların `text`/`varchar`/`String` olarak, alan-bazlı şifreleme (pgcrypto/bytea) olmadan
  tutulması. Kod içinde token/secret'ın düz DB kolonuna yazılması da yakalanır.
- **A01/A05 — Eksik RLS** (`a01-missing-rls`): Supabase/Postgres SQL migration'larında `public`
  tablolarının hiç `enable row level security` almaması veya RLS açık olup hiç policy olmaması.
  (service_role anahtarının client'ta kullanımı ayrıca `a01-supabase-service-role-key` ile.)
- **KVKK/GDPR özel nitelikli veri** (`kvkk-special-category-data`, info): sağlık/biyometrik/genetik/
  din/etnik/cinsel/ceza alanları tespit edilince KVKK md.6 açık rıza + ek koruma hatırlatması.
- **A02 — Git geçmişine gömülü secret** (`a02-secrets-git-history`): `git log -p` üzerinden
  commit'lenmiş `.env` ve yüksek-entropili/sağlayıcı-paternli anahtarlar.
- **A01 — Open redirect** (`a01-open-redirect`), **CSRF eksik** (`a01-csrf-missing`),
  **Mass assignment** (`a01-mass-assignment`).
- **A08 — Harici script'te SRI yok** (`a08-external-script-no-sri`);
  **A07 — JWT algoritma karışıklığı** (`a07-jwt-weak-verification` içine eklendi).
- **A09 — security.txt yok** (`a09-security-txt-missing`, info, RFC 9116).

Her bulgu artık uygulanabildiğinde `cwe` etiketi ve `remediationCode` (kısa düzeltme örneği)
alanlarını da taşır (JSON raporuna geriye-uyumlu, yalnızca eklenen alanlar).

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
