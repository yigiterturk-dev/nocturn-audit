# nocturn-audit

> ⚠ Bu Türkçe belge özet niteliğindedir ve İngilizce [README.md](README.md)
> kadar güncel olmayabilir. Araç arayüzü İngilizcedir.

Kendi projelerini **pentestçi metodolojisiyle** denetleyen tek bir CLI.
OWASP Top 10 (2021) eşlemeli. **Sadece tespit + raporlama** — exploit yok,
DoS yok, evasion yok.

```bash
npm install && npm run build
npx nocturn-audit init    # targets.json olustur
npx nocturn-audit scan    # hepsini tara
```

📘 **Ekip için:** [docs/EKIBE-BASLANGIC.md](docs/EKIBE-BASLANGIC.md) ·
[docs/RAPOR-NASIL-OKUNUR.md](docs/RAPOR-NASIL-OKUNUR.md)

**Bugünkü ölçüm (2026-09-23):** 83 kural (70 statik + 13 canlı) · 731 test ·
dış-precision %82 (ilk koşuda %36'ydı) · `npm run verify` kapısı yeşil.

## Bu araç neyi farklı yapıyor

Çoğu tarayıcı tek soruyu sorar: "desen eşleşti mi?". Bu araç dört soruyu
birden sorar ve dördünü de **ölçer**:

| Soru | Nasıl cevaplanıyor | Şu anki değer |
|---|---|---|
| Yazmadığım kodda doğru mu? | 4 yabancı repo (flask, express, fastapi-template, vercel/commerce) — [deney](docs/dis-precision-2026-09-23.md) | **%82** (18 TP / 4 FP) |
| Bulduğu doğru mu? | Etiketli korpus (`npm run precision`) | **%81** (95 TP / 22 FP, 12 proje) |
| Kaçırdığı var mı? (statik) | Canary — kasten açık bırakılmış iki proje | 70 statik kuralın **48**'i ölçülüyor |
| Kaçırdığı var mı? (canlı) | Canlı canary — kasten açık yerel sunucu | 13 canlı kuralın **10**'u ölçülüyor |
| Bakamadığı yer var mı? | Ölçüm sözleşmesi — kural ön koşulunu beyan eder | raporda "ölçülemedi" satırı |
| Düzeltme gerçek mi? | `npm run fark` — dosya değişmediyse düzeltme sayılmaz | `exit 1` |

Bunlar süs değil. Hepsi, aracın **kendi yaptığı** bir hatadan doğdu:

- Canlı problar Vercel'in bot duvarını uygulama sanıp 28 sahte bulgu üretti
  → ölçüm sözleşmesi
- Bir SSRF açığına fren eklendi, bulgu kayboldu, "düzeldi" sanıldı — oysa
  kuralın satır penceresi kaymıştı → `fark` komutu
- Kural sıkılırken `formData` taint listesinden düştü, mass assignment
  görünmez oldu, hiçbir test yakalamadı → canary
- Bir HTTP zaman aşımı (`timeout=120`) SQLite busy_timeout sanıldı ve gerçek
  bulgu sessizce kayboldu → isabet kapısı bunu yakaladı

## Sözleşme: bulgu yokluğu ≠ temiz

Bir kural `[]` döndürdüğünde bu **yalnızca** "baktım, temiz" demektir.
Bakamadıysa öyle der:

```
⃠ ölçülemedi (2 kural): SQL şema/migration dosyası yok — a01-missing-rls, a04-fk-cascade-off
```

Her kural neye ihtiyacı olduğunu (`git`, `sql`, `js`, `canli`…) **beyan etmek
zorundadır**; motor ön koşulu sınar, karşılanmıyorsa kuralı çalıştırmaz ve
raporda boşluk olarak gösterir. Beyansız kural test kapısından geçemez.

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
      "name": "ornek-uygulama",
      "path": "~/code/ornek-uygulama",
      "url": "https://ornek-uygulama.example.com",
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
npx nocturn-audit scan ornek-uygulama     # tek proje
npx nocturn-audit scan --static      # sadece kod taraması (canlıya dokunma, deps de atlanır)
npx nocturn-audit scan --live-only   # sadece canlı HTTP problar
npx nocturn-audit scan --no-deps     # npm audit adımını atla
npx nocturn-audit list               # kayıtlı projeleri göster
npx nocturn-audit rules              # aktif kural setini göster
npx nocturn-audit standards          # Nocturn Standartları kontrol listesini göster
npx nocturn-audit standards <proje>  # standart profili çalıştır (rapor dosyası YAZMAZ)
npx nocturn-audit diff <önceki.json> <sonraki.json>   # iki raporu karşılaştır
```

### Canary — kural sıkarken körlük yaratmıyoruz, ölçüyoruz

`test/canary/` kasten açık bırakılmış küçük bir projedir: auth'suz yazan rota,
form gövdesiyle CSRF, mass assignment, SQL enjeksiyonu, komut enjeksiyonu,
SSRF, ölçülmeyen sağlık durumu, düz metin TC/IBAN kolonu, korumasız
`JSON.parse`. `npm test` her koşuda bunların hepsinin hâlâ yakalandığını
doğrular.

**Neden gerekli:** bir denetim aracını iyileştirirken tek yönü ölçmek kolaydır
— yanlış pozitif azaldı mı. Ama bulgu sayısının düşmesi tek başına iyi haber
değildir: susturulmuş bir kural da bulgu sayısını düşürür. Canary ters soruyu
sorar. Kurulduğu ilk koşuda mass assignment kuralının form gövdesini artık
GÖRMEDİĞİ ortaya çıktı — bir önceki sıkmada `formData()` taint listesinden
düşmüştü ve hiçbir test bunu yakalamıyordu.

Kural: bir kural sıkıldığında canary'ye o açığın gerçekçi bir örneği eklenir.
Fikstür yazarın hayal ettiği açıktır; canary "sahada böyle görünür" dediğimiz
biçimdir.

### `fark` — "bulgu kayboldu" ile "açık kapandı" aynı şey değildir

Bir denetim aracının en tehlikeli anı, bulgunun sessizce kaybolduğu andır.
25 Ağustos'ta bu bizzat yaşandı: Gama'nın SSRF açığına fren eklemek için üç
satır yazıldı, sonraki koşuda bulgu yoktu — ama düzelen kod değil, kuralın
±6 satırlık penceresiydi. Açık yerinde duruyordu.

`fark` bu ayrımı yapar. Rapor artık bulgu taşıyan dosyaların içerik özetini
saklıyor; bir bulgu kaybolduğunda dosya hiç değişmemişse **düzeltme sayılmaz**
ve komut `exit 1` verir:

```
⚠ 3 bulgu kayboldu ama DOSYA HİÇ DEĞİŞMEDİ — bunlar düzeltme SAYILMAZ.
  Kod aynıysa değişen şey kuraldır. Açık büyük olasılıkla yerinde duruyor.
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
- **Hız** (kaynak: feedback_hiz_standardi / Eta 1.47s→0.26s vakası): Vercel
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

## İşleyiş bütünlüğü kuralları (`int-*`)

OWASP kuralları "birisi içeri girebilir mi" diye sorar. Bu aile başka bir şey
sorar: **sistem iyi olduğunu söylüyor ama değil mi?**

Bir denetimde bulunan on iki arızanın hiçbiri klasik bir güvenlik açığı
değildi. Hepsi aynı kalıptandı: bir yerde bir şey *kontrol ediliyor gibi*
duruyordu. Zamanlayıcı kuruluydu ama çalışmanın sonucuna kimse bakmamıştı.
Sayaç sabit yazılmıştı, saydığı şey kaybolsa da tutuyordu. Test dosyası vardı
ama listede olmadığı için hiç koşmuyordu.

| Kural | Yakaladığı |
| --- | --- |
| `int-hardcoded-status` | Durum bilgisi ölçülmüyor, sabit yazılmış |
| `int-hand-enumerated-test-list` | Test komutu dosyaları sayıyor; yeni test hiç koşmaz |
| `int-generated-file-hand-edited` | Üretilen dosyaya elle ekleme; yeniden üretimde kaybolur |
| `int-contract-two-writers` | Aynı sözleşmeyi biri tipsiz iki yer yazıyor |
| `int-scope-hand-enumerated` | Kapsamlayıcı elle sayıyor; yeni koleksiyon sızar |
| `int-permission-after-validation` | Yetki kontrolü doğrulamadan sonra |
| `int-update-guard-without-delete` | UPDATE kapalı, DELETE açık |
| `int-session-revoke-missing` | Erişim kesiliyor, oturum kapatılmıyor |
| `int-backup-without-restore-rehearsal` | Yedek var, geri yükleme provası yok |
| `int-alert-target-missing` | İzleyici var, alarm hedefi yok |
| `int-static-page-strict-csp` | `strict-dynamic` altında statik sayfa — script'ler ölü |
| `int-scan-after-write` | Zararlı yazılım taraması yazmadan sonra |
| `int-live-health-endpoints` | Sağlık ucu hata dönüyor (canlı) |
| `int-live-page-nonce-coverage` | Nonce'suz script — sayfa ölü (canlı) |
| `int-sql-dialect-leftover` | Göçten kalan lehçe artığı — sorgu çalışma anında patlar |
| `a02-pii-in-repo` | Gerçek kişilerin verisi depoda (ve git geçmişinde) |
| `a02-pii-in-generated-output` | Üretilen çıktıya gömülü kişisel veri, git'te |
| `a02-pii-in-commit-messages` | Kişisel veri commit mesajlarında |
| `int-pii-in-logs` | Kişisel veri log'a yazılıyor (7 dil) |
| `int-page-api-auth-divergence` | Sayfa, hedef kitlesinin kimlik yolunu çağırmıyor |
| `int-unbound-session-fallthrough` | Bağsız oturum reddedilmiyor, varsayılan kimliğe düşüyor |
| `int-status-from-config-not-probe` | Bağlantı durumu yapılandırmadan türetiliyor, ölçümden değil |
| `int-gate-condition-too-broad` | Kapanma koşulu kapının kapsamından geniş |

### Kural eklerken tek şart

**BAD fikstürü olmayan kural bu depoya girmez.** Ateşlemeyen kural, kural
değildir: ölçemediği şey için sessiz kalan bir kontrol "temiz" demez, hiçbir
şey demez — ve kural sayısı arttıkça bu yanılgı büyür.

Her kural en az iki fikstür ister: kuralı ateşleyen bir BAD, ve ateşlememesi
gereken bir CLEAN. Üçüncüsü sık gerekir: kuralın kaçmasına yol açabilecek
**tuzak** vakası. Örnek olarak `static-page-strict-csp` kuralının yorum-tuzağı
testine bak — o iddia, aynı hatayı gerçekten yaptığımız için orada duruyor.

Fikstür yetmez: **kuralı gerçek bir projeye koştur.** `contract-two-writers`
bütün fikstürlerini geçiyordu ama gerçek kodda yazılma sebebi olan vakayı
kaçırıyordu, çünkü dosya yolu bir yardımcı fonksiyondan geliyordu.


### Canlı kurallar gerçekten ölçüyor mu?

Canlı kurallar bir üretim hedefinde **sıfır bulgu** verdiğinde bu iki anlama
gelebilir: hedef temiz, ya da kurallar hiçbir şey ölçmüyor. Ayırmanın tek yolu
BİLEREK ZAYIF bir hedef kurup kuralların ateşlediğini görmek.

Yapıldı: açıkta `.env`, yansıyan girdi, 500 dönen sağlık ucu — hepsi
yakalandı. Yani üretimdeki sıfır gerçek.

Aynı deney bir yanlış pozitif kaynağı da ortaya çıkardı: zayıf sunucu her yola
200 dönüyordu ve kural bunu "açık admin ucu" sanıyordu. SPA ve Next.js
uygulamaları da bilinmeyen yollara 200 + HTML kabuğu döner, yani bu her SPA'da
dört sahte YÜKSEK demekti. Kural artık önce var olmayan bir yolu yokluyor; o
da 200 dönüyorsa **"ölçemedim"** diyor, "bulgu yok" demiyor.

### Geri çağırma (recall) — kaçırdığını da ölç

Yanlış pozitifi ölçmek yarısı. Öteki yarısı: araç neyi GÖRMÜYOR?

2026-08-23'te elle yapılan bir denetim 13 gerçek arıza buldu. Araç o gün
6'sını yakalayabilirdi (%46). Eksikler kurala çevrildikçe bu sayı yükseliyor;
bu bölüm güncel tutulmalı, çünkü **kaçırılanların listesi yol haritasıdır.**

Hâlâ kaçırılanlar (kural yok):
- Kesinleşmiş kaydın değiştirilebilmesi (yalnız DELETE tarafı kapsanıyor)
- Çift taraflı kayıtta denge kuralının olmaması
- Kapanma koşulunun fazla geniş olması (bir rolün daveti ötekini kilitliyor)

Kapatılanlar: lehçe artığı (`int-sql-dialect-leftover`), sayfa/API kimlik
ayrışması (`int-page-api-auth-divergence`), bağsız oturum (`int-unbound-session-fallthrough`), yapılandırmadan türetilen durum (`int-status-from-config-not-probe`), fazla geniş kapanma koşulu (`int-gate-condition-too-broad`). Geri çağırma %46 → %100 (bu turun 13 arızası için).


### Türkçe ve `\b` tuzağı

JavaScript'te `\b` kelime sınırı yalnız ASCII harflerini bilir. `bağlı`
kelimesi `ı` ile bittiği için `/\bbağlı\b/` **hiç eşleşmiyor**. Bu depoda iki
kural bu yüzden Türkçe metni göremedi ve ikisi de tam olarak yazılma sebebi
olan satırı kaçırdı.

Kural: Türkçe içerik arayan hiçbir desende `\b` kullanma. Sınırı elle yaz
(`[^A-Za-zÇĞİÖŞÜçğıöşü]`) ya da kontrolü dizenin içinde yap.
