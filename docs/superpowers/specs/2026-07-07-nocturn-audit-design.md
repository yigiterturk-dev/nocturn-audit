# nocturn-audit — Güvenlik Denetim Aracı (Design Spec)

**Tarih:** 2026-07-07
**Sahip:** Yiğit
**Amaç:** Yiğit'in tüm projelerini (Next.js / Vite + Supabase / Neon / Clerk) benden bağımsız,
gerçek bir pentestçi metodolojisiyle denetleyebileceği tek bir CLI aracı.

---

## 1. Genel Bakış

`nocturn-audit`, tek bir Node.js + TypeScript CLI'dır. Merkezi bir kayıttan (`targets.json`)
tüm projeleri tanır, her birini **statik (kod okuma)** ve **canlı (HTTP prob)** olarak tarar,
sonuçları tek bir HTML + JSON raporda toplar.

Araç bir **pentestçi gibi davranır**: bulguları OWASP Top 10 (2021) kategorilerine eşler,
severity + CVSS-benzeri puan verir, her bulguya kanıt (dosya:satır ya da HTTP istek/yanıt) ve
düzeltme önerisi ekler.

**Yetki sınırı:** Canlı testler YALNIZCA Yiğit'in sahibi olduğu, `targets.json`'da açıkça
`owned: true` işaretli URL'lere yapılır. Yıkıcı olmayan, düşük yoğunluklu problar. Başka hedef yok.

---

## 2. Mimari (izole modüller)

```
nocturn-audit/
├─ targets.json           # tüm projeler: path + canlı URL + stack + owned bayrağı
├─ src/
│  ├─ cli.ts              # komutlar: scan, list, report, rules
│  ├─ registry.ts         # targets.json okur + eksikse otomatik keşfeder (stack tespiti)
│  ├─ core/
│  │  ├─ finding.ts       # Finding tipi: id, title, severity, owasp, evidence, remediation
│  │  ├─ severity.ts      # critical/high/medium/low/info + skorlama
│  │  ├─ engine.ts        # kuralları yükler, çalıştırır, bulguları toplar
│  │  └─ rule.ts          # Rule arayüzü (her kural bunu implement eder)
│  ├─ static/             # kod tarayıcı kuralları (her kural ayrı dosya + test)
│  ├─ live/               # canlı HTTP prob kuralları (her kural ayrı dosya + test)
│  ├─ deps/               # bağımlılık zafiyet tarayıcı (npm audit sarmalayıcı)
│  └─ report/             # html.ts, json.ts, terminal.ts
├─ test/                  # her kuralın fixture'lı testi
└─ docs/superpowers/specs/
```

**Kural arayüzü (tek amaçlı birim):** Her kural bir `Rule` nesnesidir —
`{ id, title, owasp, severity, run(context): Finding[] }`. Yeni açık türü = yeni dosya,
motora dokunmadan. Bu, aracın zamanla büyümesini kolaylaştırır.

---

## 3. Pentester Metodolojisi — Kontrol Kapsamı (OWASP Top 10 2021 eşlemeli)

### A01 — Broken Access Control (statik + canlı)
- API route'larında auth kontrolü var mı (`app/api/**/route.ts`, `pages/api`)
- IDOR paterni: `params.id` / query param ile doğrudan sorgu, ownership kontrolü yok
- Supabase client'ta `service_role` key kullanımı (RLS bypass riski)
- Canlı: 2 test hesabıyla yatay yetki testi (A'nın kaynağına B erişebiliyor mu)
- Canlı: `/admin`, `/api/*` auth'suz açılıyor mu

### A02 — Cryptographic Failures (statik + canlı)
- Hardcoded secret / API key / token (entropy + pattern tabanlı)
- `.env` git'e commit edilmiş mi, `.gitignore`'da mı
- `NEXT_PUBLIC_` altında gizli anahtar (client'a sızıyor)
- Zayıf hash (md5/sha1 parola), sabit JWT secret
- Canlı: HSTS eksik, cookie'de Secure/HttpOnly/SameSite eksik

### A03 — Injection (statik + canlı)
- String ile SQL (template literal içine kullanıcı girdisi)
- `dangerouslySetInnerHTML`, `eval`, `Function()`, `child_process` + girdi
- NoSQL / ORM ham sorgu enjeksiyon paternleri
- Canlı: yansıyan XSS ve hata tabanlı probe (yıkıcı olmayan işaretleyici payload)

### A04 — Insecure Design
- Rate limit / brute-force koruması hiç yok (login, OTP, ödeme uçları)
- Kaptcha / throttling eksik hassas akışlar

### A05 — Security Misconfiguration (statik + canlı)
- `next.config` security header'ları eksik (CSP, X-Frame-Options, X-Content-Type)
- CORS `*` / kimlik bilgili CORS
- Debug/verbose/stacktrace prod'da açık
- Canlı: header seti taraması, açıkta kalan `.env`/`.git`/kaynak map

### A06 — Vulnerable & Outdated Components (deps)
- `npm audit --json` sarmalayıcı → kritik/yüksek CVE'li paketler
- Terk edilmiş / güncelliğini yitirmiş major bağımlılıklar

### A07 — Identification & Authentication Failures (statik + canlı)
- Zayıf parola politikası, session sabitleme
- JWT doğrulama eksik/yanlış (`none` alg, imza kontrolsüz)
- Canlı: login rate limit, hesap sayımı (user enumeration) sızıntısı

### A08 — Software & Data Integrity Failures
- Doğrulanmamış webhook (Stripe/iyzico/Meta imza kontrolü yok)
- CI/deploy'da güvensiz kaynak

### A09 — Security Logging & Monitoring Failures
- Auth/ödeme olaylarında audit log var mı (bilgilendirici seviye bulgu)

### A10 — Server-Side Request Forgery (SSRF)
- Kullanıcı girdisiyle sunucu taraflı `fetch`/istek (allowlist yok)

---

## 4. Rapor

- **Terminal:** renkli özet — proje bazında kritik/yüksek/orta/düşük/bilgi sayıları + toplam skor
- **`report/<tarih>.html`:** proje proje, OWASP kategorili, her bulgu için:
  kanıt (dosya:satır ya da HTTP istek/yanıt), severity, düzeltme önerisi
- **`report/<tarih>.json`:** makine okunur (ileride CI'a bağlanabilir)
- **Çıkış kodu:** kritik bulgu varsa `exit 1` → deploy öncesi gate olarak kullanılabilir

---

## 5. Kullanım

```bash
npx nocturn-audit scan                 # tüm projeleri tara (statik + canlı + deps)
npx nocturn-audit scan Beta       # tek proje
npx nocturn-audit scan --static        # sadece kod (canlıya hiç dokunma)
npx nocturn-audit scan --live-only     # sadece canlı problar
npx nocturn-audit list                 # kayıtlı projeleri göster
npx nocturn-audit rules                # aktif kural setini göster
```

---

## 6. `targets.json` Örneği

```json
{
  "projects": [
    {
      "name": "Beta",
      "path": "~/Desktop/Web Siteleri/Beta",
      "url": "https://Beta.vercel.app",
      "owned": true,
      "stack": { "framework": "next", "db": "supabase", "auth": "clerk" }
    }
  ]
}
```

`owned: false` ya da alan eksikse → o proje için canlı test atlanır, sadece statik çalışır.

---

## 7. Kapsam Dışı (YAGNI)

- Başkasına ait hedeflere karşı test — kesinlikle yok
- Yıkıcı/DoS/fuzzing yükü — yok, sadece düşük yoğunluklu doğrulayıcı probe
- Otomatik exploit / kalıcı erişim — yok; araç yalnızca **tespit + raporlama** yapar
- Detection evasion — yok

---

## 8. Teknoloji

- Node.js 20+ / TypeScript
- Bağımlılıklar minimum: `commander` (CLI), `fast-glob` (dosya tarama), `picocolors` (terminal),
  yerleşik `fetch` (canlı prob). Ağır güvenlik SDK'sı yok — kurallar kendi mantığıyla çalışır.
- Test: `vitest` + fixture dosyaları (her kural için bilinçli açıklı örnek kod)
```

