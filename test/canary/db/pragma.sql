-- HOLE 27 — SQLite CASCADE declared but the foreign_keys PRAGMA never enabled.
CREATE TABLE siparis_kalemleri (
  id INTEGER PRIMARY KEY,
  siparis_id INTEGER REFERENCES siparisler(id) ON DELETE CASCADE
);
