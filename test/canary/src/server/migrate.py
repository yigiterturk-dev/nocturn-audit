import sqlite3

DB = "veri.db"

# ACIK 28 — cok yazarli SQLite'ta kilit bekleme suresi ayarlanmamis
#            ("database is locked" riski). Yorumda ANAHTAR KELIME yazmiyoruz:
#            kural yorumu okursa kendini kandirmis olur.
# ACIK 29 — sema/DDL hatasi ciplak except ile yutuluyor (sessiz basarisizlik):
#   sutun eklenemezse kimse gormez, sonraki sorgu patlar.
def semayi_kur():
    while True:
        conn = sqlite3.connect(DB)
        conn.execute("INSERT INTO kayitlar VALUES (1)")
        try:
            conn.execute("ALTER TABLE kayitlar ADD COLUMN durum TEXT")
        except:
            pass
        conn.commit()
