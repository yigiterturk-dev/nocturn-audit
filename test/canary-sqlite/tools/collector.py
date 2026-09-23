import json
import sqlite3
import urllib.request

DB = "veri.db"

# ACIK — cok yazarli SQLite'ta kilit bekleme suresi ayarlanmamis.
# ACIK — dis JSON try olmadan parse ediliyor: tek bozuk kayit tum turu dusurur.
# ACIK — kisisel veri log'a duz yaziliyor.
def tur():
    while True:
        conn = sqlite3.connect(DB)
        with urllib.request.urlopen("https://ornek.test/kayitlar", timeout=30) as c:
            kayitlar = json.loads(c.read())
        for k in kayitlar:
            print("Kayit isleniyor: %s (%s)" % (k["eposta"], k["telefon"]))
            conn.execute(
                "INSERT INTO kayitlar (eposta, ad) VALUES (?, ?)", (k["eposta"], k["ad"])
            )
        conn.commit()
