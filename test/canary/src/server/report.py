import sqlite3

# HOLE 25 — a SQL column/table name built by string concatenation.
# Parametreleme SUTUN ADINI korumaz: ? yalnizca degerler icindir.
def sirala(conn, tablo, sutun, yon):
    return conn.execute(f"SELECT * FROM {tablo} ORDER BY {sutun} {yon} LIMIT 100").fetchall()

def guncelle(conn, alan, deger, kayit_id):
    conn.execute(f"UPDATE musteriler SET {alan} = ? WHERE id = ?", (deger, kayit_id))
