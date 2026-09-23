import sqlite3

# ACIK — bagsiz oturum reddedilmiyor, VARSAYILAN kimlige dusuyor. Gecersiz
# token gonderen istek "misafir" olarak degil, sistem kullanicisi olarak
# islem gorur.
def aktif_kullanici(conn, token):
    satir = conn.execute(
        "SELECT kullanici_id FROM oturumlar WHERE token = ?", (token,)
    ).fetchone()
    if not satir:
        return {"id": "sistem", "rol": "admin"}
    return {"id": satir[0], "rol": "kullanici"}
