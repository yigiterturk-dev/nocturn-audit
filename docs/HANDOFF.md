# 🌙 NOCTURN EL KİTABI — 23 Eylül 2026 gece oturumu teslimi

> Bu doküman: bugün kurulan tüm yapıların haritası. Başka bir oturumdan devam
> etmek için tek referans. (Bu dosya PRIVATE — public repoya ASLA gitmez.)

## 1. Repolar ve durumlar

| Repo | Konum | Durum |
|---|---|---|
| **nocturn-audit** (private kaynak) | `~/projects/nocturn/packages/nocturn-audit` | monorepo içinde, 729 test, korpus %100 etiketli |
| **nocturn-audit** (PUBLIC) | `~/projects/nocturn-audit-public` → github.com/yigiterturk-dev/nocturn-audit | **v0.1.4 canlı** · export: `bash scripts/export-public.sh ../nocturn-audit-public` |
| **nocturn-gateway** (public SDK) | `~/projects/nocturn-gateway` → github.com/yigiterturk-dev/nocturn-gateway | **v0.1.1** · TS+PY istemci |
| KAPI servisi | netcup `/opt/ai-gateway/kapi.py` (arşiv: `packages/nocturn-audit/deploy/kapi.py`) | systemd `kapi.service` |

**Export kuralları (KRİTİK):** korpus (labels/bug-db), targets.json, .env*,
codenames, denetim defteri, pislik haritası, superpowers, runbook — HEPİSİ
dışlanır. Export sonrası refuse-check müşteri adı bulunca REDDEDER. `sed -i`
KULLANMA — bind mount inode'u bozulur (bugün yaşandı: caddy eski dosyayı
görüp 3 saat backoff'a girdi; çözüm `docker restart legafetch-caddy`).

## 2. VPS haritası (iki kutu)

| | **Hetzner** 89.167.52.36 | **Netcup** 159.195.158.36 |
|---|---|---|
| SSH | `ssh root@89.167.52.36` (port 22 — 23 DEĞİL) | `ssh netcup` (config'de alias, key: id_ed25519_netcup) |
| İçerik | lexordo, bir marka yonetim SaaS (laya+laya-guard), bir SaaS projesi, clamav, fail2ban | **LegaFetch** (api+web+caddy+autoheal), **insurefetch**, **AI Gateway** |
| Disk | %80 dolu ⚠️ | %14 (1TB) |
| Roller | müşteri işleri | AI/veri merkezi + KAPI |

## 3. AI Gateway — ai.nocturndev.com (CANLI, TLS'li)

**Mimari:** tüm projeler → Caddy (netcup) → Jev (typesafe.ai proxy, anahtar
gateway'de) + Laya (autossh-tünel → Hetzner 127.0.0.1:8000, internete kapalı).

**Dağıtım satırları** (anahtar: netcup `/opt/ai-gateway/.env`, chmod 600 —
2026-09-23'te DÖNDÜRÜLDÜ, eskisi public repoya sızıp öldü):
```
AI_GATEWAY_URL=https://ai.nocturndev.com
AI_GATEWAY_KEY=<.env dosyasından>
```

**Uçlar (X-Gateway-Key ister, yoksa 401):**
- `POST /jev/v1/systemone` — Jev skorlama (state+questions → noul)
- `POST /laya/predict|triage|guard|sort` — Laya karar motoru
- `GET /laya/health` — model: convaiinnovations/laya (multilingual)
- `POST /nobet/beat` + `GET /nobet/durum` — heartbeat + SESSİZ deadman tablosu
- `POST /maske` — KVKK maskeleme (TCKN/IBAN/tel/e-posta/ad-soyad)
- `GET /sir/<proje>` — sır kasası okuma (yazma: netcup'ta
  `/opt/ai-gateway/data/sirlar/<proje>.json`)
- `POST /kota/<proje>` — kullanım sayacı

**Bileşenler:** systemd `ai-tunnel.service` (netcup: 172.18.0.1:8100 →
hetzner:8000) · systemd `kapi.service` (172.18.0.1:8787) · Caddyfile son
bloğu `/opt/legafetch/caddy/Caddyfile` (yedek: Caddyfile.bak-*) · ufw:
172.18.0.0/16 → 8100+8787.

## 4. Dersler (tekrar yaşanmasın)

1. **`.exec(` metod çağrısı** SQLModel/RegExp'te var — lookbehind ile ayrıldı
2. **PyJWT `jwt.decode(key, algorithms=)`** imzayı DOĞRULAR (JS decode-only değil)
3. **`cache()` sarmallı kapılar** auth keşfine düşmez — TANIM genişletildi
4. **`T00:00:00Z` vs `T00:00:00`** — kasıtlı UTC vs yerel gece yarısı ayrımı
5. **`sed -i` + bind mount** = konteyner bayat dosya görür → restart
6. **Yol bazlı kural daraltma** canary'yi kırar — canary her şeyin hocası
7. **Jev'e aritmetik verilmez** — eşik kodda (legafetch doktrini)

## 5. Korpus & ölçüm

- İç korpus: **95 TP + 7 düşük-TP / 22 FP (hepsi gerekçeli) / 0 canlı "?"**
- İç precision: **%81** · kapı: `npm run precision:ci` (EXIT 0)
- **Dış precision**: 4 OSS repo (flask/express/fastapi-template/vercel-commerce)
  44→25 bulgu, **%36→%82** — deney: `docs/dis-precision-2026-09-23.md`
- Jev triyaj: korpusa YAZMAZ — öneri üretir (`npm run jev-triyaj`)

## 6. Acil/kalan işler

| İş | Kim |
|---|---|
| OpenAI + Google anahtar REVOKE (hub) | kullanıcı |
| Vercel BLOB token döndür (stackcrm) | kullanıcı |
| stackcrm git geçmişi temizliği (redactor + force-push) | kullanıcı onayıyla |
| Hetzner disk %80 → temizlik | yapılabilir |
| Dış FP kalan 4: prose prop-API, şablon build, 2 framework-deseni | roadmap |
| helper-keşif genelleştirmesi (auth→tüm kapılar) | en büyük refactor |

## 7. Komut çıpası

```bash
cd ~/projects/nocturn/packages/nocturn-audit
npm run verify        # build + test + precision:ci (tek komut sağlık)
npm run precision     # korpus ölçümü
npm run jev-triyaj    # JEV_AI_API_KEY ile korpus ön-triyajı
NOCTURN_LANG=tr|en    # rapor dili
bash scripts/export-public.sh ../nocturn-audit-public   # yayına çıkarma
```
