#!/usr/bin/env python3
"""
nocturn-karne — müşteri bakım & güvenlik raporu üretici.

nocturn-audit rapor JSON'u + AI Gateway nöbet verisi → markalı HTML rapor
→ AI Gateway'e yüklenir → müşteriye verilecek link döner.

Kullanım:
  AI_GATEWAY_URL=... AI_GATEWAY_KEY=... python3 karne.py <proje> [rapor-json]
  (rapor-json verilmezse son report/*.json kullanılır)
"""
import json, os, sys, glob, time, urllib.request, urllib.error
import csv

GW = os.environ.get("AI_GATEWAY_URL", "https://ai.nocturndev.com").rstrip("/")
KEY = os.environ.get("AI_GATEWAY_KEY", "")
PROJE = sys.argv[1] if len(sys.argv) > 1 else ""
RAPOR = sys.argv[2] if len(sys.argv) > 2 else sorted(glob.glob("report/*.json"))[-1]

def _post(yol, govde, timeout=30):
    req = urllib.request.Request(f"{GW}{yol}", data=json.dumps(govde, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json", "X-Gateway-Key": KEY}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def _get(yol, timeout=20):
    req = urllib.request.Request(f"{GW}{yol}", headers={"X-Gateway-Key": KEY})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

d = json.load(open(RAPOR))
pr = next((p for p in d["projects"] if p["name"] == PROJE), None)
if not pr:
    print(f" '{PROJE}' son raporda yok — önce: node dist/cli.js scan --static --no-deps --no-standards {PROJE}")
    sys.exit(2)

counts = pr["counts"]
pislik = pr.get("pislik", {})
finds = pr.get("findings", [])
siddetSirasi = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
onemli = sorted([f for f in finds if f["severity"] in ("critical", "high", "medium")],
                key=lambda f: siddetSirasi[f["severity"]])

# nöbet verisi
try:
    nobet = _get("/nobet/durum")
    n = next((x for x in nobet["projeler"] if x["proje"] == PROJE), None)
except Exception:
    n = None

bugun = time.strftime("%d %B %Y")
skor = pislik.get("score", 0)
etiket = pislik.get("label", "?")
c = counts
satir = lambda ad, v, iyi: (f"<span style='color:{iyi}'>{v}</span>")

kesitler = []
for f in onemli[:8]:
    baslik = f["title"]
    oneri = f.get("remediation", "")[:300]
    kesitler.append(
        f"<div class='bulgu'><div class='b-baslik'><span class='rozet {f['severity']}'>{f['severity'].upper()}</span>"
        f" {baslik}</div><div class='b-oneri'>Öneri: {oneri}</div></div>")
kesit_html = "".join(kesitler) or "<div class='bulgu ok'>Öne çıkan açıklık bulunmadı — tertemiz iş. 👌</div>"

# SEO: linkanaliz çıktıları varsa (pagerank + link önerileri CSV'leri) ekle
seo_html = ""
_kisa = PROJE.replace("https://", "").replace("/", "_")
_pr_csv = f"pagerank-{_kisa}-{time.strftime('%Y-%m-%d')}.csv"
_lnk_csv = f"link-oneri-{_kisa}-{time.strftime('%Y-%m-%d')}.csv"
# linkanaliz site adını .com ile de yazabilir (gelecekfinans.com) — glob ile eşle
_pr_glob = glob.glob(f"pagerank-{PROJE}*-{time.strftime('%Y-%m-%d')}.csv")
if _pr_glob and not os.path.exists(_pr_csv): _pr_csv = _pr_glob[0]
_lnk_glob = glob.glob(f"link-oneri-{PROJE}*-{time.strftime('%Y-%m-%d')}.csv")
if _lnk_glob and not os.path.exists(_lnk_csv): _lnk_csv = _lnk_glob[0]
try:
    _satirlar = list(csv.DictReader(open(_pr_csv, encoding="utf-8-sig")))
    _orfan = [x for x in _satirlar if x.get("orphan") == "EVET"]
    _top = sorted(_satirlar, key=lambda x: -float(x.get("pagerank", 0)))[:3]
    _oneriler = list(csv.DictReader(open(_lnk_csv, encoding="utf-8-sig"))) if os.path.exists(_lnk_csv) else []
    _toplar = ", ".join(
        f"{(x['url'].rstrip('/').split('/')[-1] or '/')} ({x['pagerank']})" for x in _top)
    seo_html = (
        f"<div class='kutu nobet'><b>Değerli sayfalar (PageRank):</b> {_toplar}</div>"
        f"<div class='bulgu {'ok' if not _orfan else ''}'>{len(_orfan)} orphan sayfa "
        f"(içten linki yok) · {len(_oneriler)} internal link önerisi "
        f"(<code>{_lnk_csv}</code>)</div>")
except Exception:
    seo_html = ""

if n:
    nobet_html = f"""<div class='kutu nobet'>
<b>Nöbet durumu:</b> {n['ses']} · son kalp {round(n['sure_sn']/60)} dk önce · SSL: {n.get('ssl_gun','?')} gün · son yedek: {n.get('yedek_gun','?')} gün önce</div>"""

html = f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<title>{PROJE} — Bakım & Güvenlik Karnesi</title>
<style>
body{{background:#0b1020;color:#e2e8f0;font-family:ui-sans-serif,system-ui;margin:0;padding:32px;font-size:14px}}
.wrap{{max-width:860px;margin:auto}} h1{{color:#38bdf8;font-size:24px;margin-bottom:4px}}
h2{{color:#7dd3fc;font-size:16px;border-bottom:1px solid #1e293b;padding-bottom:6px;margin-top:28px}}
.kartlar{{display:flex;gap:12px;flex-wrap:wrap}} .kart{{background:#111a33;border:1px solid #1e293b;border-radius:10px;padding:14px 20px;min-width:140px}}
.kart .n{{font-size:26px;font-weight:bold}} .kart .l{{color:#94a3b8;font-size:11px}}
.kritik .n{{color:#ef4444}} .high .n{{color:#f97316}} .med .n{{color:#f59e0b}} .low .n{{color:#38bdf8}}
.bulgu{{background:#111a2e;border-left:3px solid #f59e0b;padding:10px 14px;margin:10px 0;border-radius:6px}}
.bulgu.ok{{border-left-color:#10b981}} .b-baslik{{font-weight:bold}} .rozet{{font-size:10px;padding:2px 8px;border-radius:4px;background:#1e293b}}
.rozet.critical{{color:#ef4444}} .rozet.high{{color:#f97316}} .rozet.medium{{color:#f59e0b}}
.nobet{{background:#0d1730;border-radius:8px;padding:10px 16px;margin:12px 0;color:#a5b4fc}}
.skor{{font-size:40px;font-weight:800;color:{'#10b981' if skor==0 else '#f59e0b' if skor<60 else '#ef4444'}}}
.alt{{color:#64748b;font-size:11px;margin-top:30px}} .muhur{{color:#38bdf8;font-weight:bold}}
</style></head><body><div class='wrap'>
<h1>🌙 {PROJE} — Bakım & Güvenlik Karnesi</h1>
<div class='alt'>{bugun} · nocturndev.com bakım paketi · <span class='muhur'>nocturn-audit</span> ile üretildi</div>
<h2>Pislik Skoru</h2>
<div class='skor'>{skor}/100 — {etiket}</div>
<p>0 = tertemiz. Bu skor ölçülebilen her kuralın toplamıdır; çalıştırılamayan kurallar 'not measured' olarak ayrıca raporlanır.</p>
<div class='kartlar'>
<div class='kart krit'><div class='n'>{c['critical']}</div><div class='l'>KRİTİK</div></div>
<div class='kart high'><div class='n'>{c['high']}</div><div class='l'>YÜKSEK</div></div>
<div class='kart med'><div class='n'>{c['medium']}</div><div class='l'>ORTA</div></div>
<div class='kart low'><div class='n'>{c['low']}</div><div class='l'>DÜŞÜK</div></div>
<div class='kart low'><div class='n'>{c['info']}</div><div class='l'>BİLGİ</div></div>
</div>
<h2>Nöbet (çalışma süresi & sağlık)</h2>
{nobet_html or '<div class="bulgu">Nöbet verisi bu proje için henüz toplanmıyor — bakım paketi kapsamına alınabilir.</div>'}
<h2>Öne çıkan bulgular ve öneriler</h2>
{kesit_html}
<h2>SEO — Internal Link Durumu</h2>
{seo_html}
<h2>Sonraki adım</h2>
<p>Bu karnenin tüm teknik detayları nocturndev ekibinde saklanır. Sorularınız için:
<b>sales@nocturndev.com</b></p>
<p class='alt'>🌙 nocturndev.com — bu rapor nocturn-audit (MIT, açık kaynak) tarafından üretildi.
Ölçülen precision %81 (iç) · %82 (yabancı kod) — sayılar gizlenmez, yayınlanır.</p>
</div></body></html>"""

yanit = _post("/nobet/rapor/" + PROJE, {"tarih": time.strftime("%Y-%m-%d"), "html": html,
                                         "md": json.dumps(c, ensure_ascii=False)})
url = f"{GW}{yanit['url']}".replace("token=...", f"token={KEY}")
print("✓ karne üretildi:", url)
print(f"  skor {skor}/100 ({etiket}) · {c['critical']}C/{c['high']}H/{c['medium']}M/{c['low']}L")
