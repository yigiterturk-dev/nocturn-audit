-- HOLE 18 — a public table without RLS enabled.
CREATE TABLE public.siparisler (
  id uuid PRIMARY KEY,
  kullanici_id uuid NOT NULL,
  tutar numeric
);
