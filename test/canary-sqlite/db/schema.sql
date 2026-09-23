-- HOLE — a dialect leftover from the migration: the project moved to SQLite but the queries
-- PostgreSQL fonksiyonları kaldı. SQLite bunları tanımaz; sorgu çalışma
-- anında patlar, testte değil (çünkü bu yol nadiren koşuluyor).
CREATE TABLE oturum_kayitlari (
  id TEXT PRIMARY KEY DEFAULT (gen_random_uuid()),
  ad TEXT,
  olusturuldu TEXT
);

SELECT string_agg(ad, ', ') AS adlar,
       to_char(olusturuldu, 'YYYY-MM-DD') AS gun
FROM oturum_kayitlari
GROUP BY gun;
