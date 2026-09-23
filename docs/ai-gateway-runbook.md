# 🌉 AI Gateway Runbook — ai.nocturndev.com (2026-09-23)

Tüm Nocturn projelerinin Jev (LLM) + Laya (karar motoru) erişimi tek kapıdan.

## Dağıtım — her projeye eklenecek

```bash
AI_GATEWAY_URL=https://ai.nocturndev.com
AI_GATEWAY_KEY=7d3ba0c0dc335663cc0d70f332d8d628e4d079c51e361a9e
```

## Uçlar

| Uç | Ne yapar | Örnek |
|---|---|---|
| `POST /jev/v1/systemone` | Jev skorlama (anahtar gateway'de) | state + questions → noul skorları |
| `POST /laya/predict` | Laya karar tahmini | body: state + questions |
| `POST /laya/triage` | Laya triyaj | aynı sözleşme |
| `POST /laya/guard` | Laya guard | — |
| `GET /laya/health` | Laya sağlık | `{"status":"ok","model":"convaiinnovations/laya"}` |

Tümü `X-Gateway-Key` header'ı ister — yoksa **401**.

## Mimari

```
proje → ai.nocturndev.com (Caddy TLS, netcup 159.195.158.36)
          ├─ /jev/*  → api.typesafe.ai   (JEV key gateway'de; projeler bilmez)
          └─ /laya/* → 172.18.0.1:8100 [ai-tunnel.service]
                          └─ ssh → hetzner 127.0.0.1:8000 (Laya, localhost-only)
```

## Bileşenler

- **Anahtar**: netcup `/opt/ai-gateway/.env` (600) — GATEWAY_KEY + JEV_UPSTREAM_KEY
- **Tünel**: netcup `ai-tunnel.service` (systemd, Restart=always) — 172.18.0.1:8100 → hetzner:8000
- **SSH anahtarı**: netcup `/root/.ssh/hetzner_tun` → hetzner authorized_keys
- **ufw**: `allow from 172.18.0.0/16 to any port 8100` (yalnız docker alt ağı)
- **Caddy**: `/opt/legafetch/caddy/Caddyfile` son bloğu (yedek: Caddyfile.bak-*)

## Arıza giderme

| Belirti | Kontrol |
|---|---|
| 401 | X-Gateway-Key header'ı eksik/yanlış |
| 502 /laya'da | tünel: `systemctl status ai-tunnel` (netcup) → restart |
| Timeout /laya'da | ufw kuralı: `allow from 172.18.0.0/16 to port 8100` |
| Jev 401 upstream | JEV_UPSTREAM_KEY döndürülmüş olabilir → .env'de güncelle |
| Sertifika sorunu | `docker restart legafetch-caddy` (backoff temizlenir) |

## KAPI v1 ek uçlar (2026-09-23)

| Uç | Ne yapar |
|---|---|
| `POST /nobet/beat` | kalp atışı (proje, durum, not) — 5 dk gelmezse "SESSIZ" |
| `GET /nobet/durum` | tüm projelerin canlı/SESSIZ tablosu |
| `POST /maske` | KVKK maskeleme: TCKN, IBAN, telefon, e-posta, ad-soyad |
| `GET /sir/<proje>` | sır kasası okuma (yazma yalnız sunucuda: data/sirlar/<proje>.json) |
| `POST /kota/<proje>` | kullanım sayacı |

Servis: netcup `/opt/ai-gateway/kapi.py` (arşivi: `deploy/kapi.py`) · systemd `kapi.service` · 172.18.0.1:8787
SDK: `nobetAt() nobetDurum() maskele() sirAl()` (TS+PY) — nocturn-gateway v0.1.1
