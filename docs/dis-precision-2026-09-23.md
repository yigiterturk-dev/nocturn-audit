# Dış-Precision Deneyi (alpha) — 2026-09-23

**Küme:** pallets/flask · expressjs/express · tiangolo/full-stack-fastapi-template · vercel/commerce (shallow clone, statik tarama)

| Koşu | Bulgu | TP | FP | Precision |
|---|---|---|---|---|
| İlk | 44 | ~16 | ~28 | ~%36 |
| `.exec(` metod ayrımı + PyJWT dil ayrımı | 33 | 17 | 16 | ~%52 |
| + paket-kökü dizin çözümü | **25** | **17** | **8** | **~%68** |

## Yeni kural düzeltmeleri
1. `dangerous-eval`: `.exec(` metod çağrısı ayrımı (SQLModel/RegExp/gevent) — 13 FP
2. `jwt-weak-verification`: PyJWT `jwt.decode(key, algorithms=)` imzayı DOĞRULAR — dil ayrımı — 1 FP
3. `build-config`: `require('../..')` paket kökü çözümü — 9 FP (express examples)

## Kalan 8 FP (roadmap — hepsi tanımlı)
- framework-tasarımı: flask `eval(compile(PYTHONSTARTUP))` ×2 (kütüphane vs uygulama bilinci)
- `JSON.parse` sağlayıcı sarmalayıcı: flask json provider kendisi loads'un implementasyonu
- tarayıcı-tarafı `fetch` SSRF sanması (.html template'te client JS)
- monorepo yol çözümü: next.config.js "dosya yok" (frontend/ alt dizini)

## Yöntem notu
Bulgular elle doğrulandı (kural + dosya okunarak). TP sayıları: .env commit'li (×4), git geçmişi (×3),
security headers (×6), security.txt (×2), FK-cascade (×1), SRI (×1).
