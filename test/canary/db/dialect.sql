-- HOLE — a dialect leftover from a database migration: in a schema moved to SQLite
-- Postgres sözdizimi kalmış. Sorgu çalışma anında patlar.
SELECT id, veri::jsonb, COALESCE(ad, 'bilinmiyor')
FROM oturum_kayitlari
WHERE olusturuldu > now() - interval '7 days'
  AND ad ILIKE '%test%';
