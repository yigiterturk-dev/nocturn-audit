#!/usr/bin/env python3
"""nocturn nöbet toplayıcı — hedef URL'leri yoklar, kalp + SSL günü gönderir,
kırıkları Telegram'a (bildir.sh) yollar. systemd timer ile 5 dakikada bir."""
import json, ssl, subprocess, time, urllib.request

VERI = "/opt/ai-gateway/data"
ENV = "/opt/ai-gateway/.env"

def cfg(alan):
    satir = [l for l in open(ENV) if l.startswith(alan + "=")]
    return satir[0].split("=", 1)[1].strip() if satir else ""

def bildir(mesaj):
    tok = cfg("TELEGRAM_BOT_TOKEN"); chat = cfg("TELEGRAM_CHAT_ID")
    if not tok or not chat:
        return
    try:
        req = urllib.request.Request(f"https://api.telegram.org/bot{tok}/sendMessage",
            data=f"chat_id={chat}&text={mesaj}".encode(), method="POST")
        urllib.request.urlopen(req, timeout=15).read()
    except Exception:
        pass

def ssl_gun(url):
    """Sertifikanın kalan günü — openssl notAfter parse (boşluklar normalize)."""
    try:
        host = url.split("//")[1].split("/")[0]
        cikti = subprocess.run(["openssl", "s_client", "-connect", f"{host}:443", "-servername", host],
                               input=b"", capture_output=True, timeout=10).stdout.decode(errors="ignore")
        from datetime import datetime, timezone
        for satir in cikti.splitlines():
            # openssl 3.x: "NotAfter: Dec 15 04:48:51 2026 GMT" (1.x'te notAfter= idi)
            if "NotAfter:" not in satir and "notAfter=" not in satir:
                continue
            ham = satir.split("NotAfter:")[-1].split("notAfter=")[-1].strip()
            tarih = " ".join(ham.split())
            for bicim in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT", "%Y-%m-%d %H:%M:%S%z"):
                try:
                    son = datetime.strptime(tarih, bicim).replace(tzinfo=timezone.utc)
                    return max(0, round((son - datetime.now(timezone.utc)).total_seconds() / 86400))
                except ValueError:
                    continue
        return None
    except Exception:
        return None
    return None

def beat(proje, govde, key):
    req = urllib.request.Request("http://172.18.0.1:8787/nobet/beat",
        data=json.dumps(govde).encode(),
        headers={"Content-Type": "application/json", "X-Gateway-Key": key}, method="POST")
    urllib.request.urlopen(req, timeout=10).read()

def main():
    key = cfg("GATEWAY_KEY")
    hedefler = json.load(open(f"{VERI}/nobet-hedefleri.json"))
    sorunlar = []
    for h in hedefler:
        proje, url = h["proje"], h["url"]
        if not url:
            continue
        try:
            kod = subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "20", "-w", "%{http_code}", url],
                                 capture_output=True, timeout=25).stdout.decode()
            gun = ssl_gun(url) or 0
            durum = "iyi" if kod == "200" else "bozuk"
            if kod != "200":
                sorunlar.append(f"{proje} → HTTP {kod}")
            if gun and gun < 14:
                sorunlar.append(f"{proje} SSL {gun} gün kaldı")
            beat(proje, {"proje": proje, "durum": durum, "ssl_gun": gun,
                         "not": f"HTTP {kod}", "url": url}, key)
        except Exception as e:
            sorunlar.append(f"{proje} → {str(e)[:60]}")
            try:
                beat(proje, {"proje": proje, "durum": "bozuk", "not": str(e)[:60]}, key)
            except Exception:
                pass
    # SESSİZ proje taraması: URL'li olmayan ama kalp gönderen projeler (5 dk sessizlik = alarm)
    try:
        req = urllib.request.Request("http://172.18.0.1:8787/nobet/durum",
            headers={"X-Gateway-Key": key})
        with urllib.request.urlopen(req, timeout=10) as r:
            durumlar = json.loads(r.read().decode()).get("projeler", [])
        sessiz = [x for x in durumlar if x.get("ses") == "SESSİZ" and x.get("durum") != "bilinmiyor"]
        # URL'siz (elle kalp atan) projeler: 30 dk sessizlik = sorun
        sessiz = [x for x in sessiz if x.get("proje") not in {h["proje"] for h in hedefler if h.get("url")} and x.get("sure_sn", 0) > 1800]
        if sessiz:
            # alarm dedup: aynı proje için 6 saatte bir (telegram spam olmasın)
            son_alarmlar = oku(f"{VERI}/nobet-alarm.json", {})
            simdi = time.time()
            taze = [x for x in sessiz if simdi - son_alarmlar.get(x["proje"], 0) > 6 * 3600]
            if taze:
                sorunlar.insert(0, "SESSİZ: " + ", ".join(x["proje"] for x in taze))
                for x in taze:
                    son_alarmlar[x["proje"]] = simdi
                yaz(f"{VERI}/nobet-alarm.json", son_alarmlar)
    except Exception:
        pass
    if sorunlar:
        bildir("🌙 NOCTURN NÖBET — sorunlar:\n" + "\n".join("• " + s for s in sorunlar))
    print(f"{time.strftime('%H:%M')} — {len(hedefler)} hedef tarandı, {len(sorunlar)} sorun")

if __name__ == "__main__":
    main()
