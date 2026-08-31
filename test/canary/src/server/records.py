import sqlite3

# ACIK 26 — check-then-act yarisi: once "var mi" diye SELECT, sonra kosullu
# UPDATE ya da INSERT. Iki istek ayni anda gelirse ikisi de "yok" gorup ikisi
# de ekler. Atomik degil; UNIQUE + ON CONFLICT gerekir.
def kullanici_kaydet(conn, email, ad):
    conn.execute("PRAGMA busy_timeout = 5000")
    mevcut = conn.execute(
        "SELECT id FROM kullanicilar WHERE email = ?", (email,)
    ).fetchone()
    if mevcut:
        conn.execute("UPDATE kullanicilar SET ad = ? WHERE id = ?", (ad, mevcut[0]))
    else:
        conn.execute("INSERT INTO kullanicilar (email, ad) VALUES (?, ?)", (email, ad))
    conn.commit()
