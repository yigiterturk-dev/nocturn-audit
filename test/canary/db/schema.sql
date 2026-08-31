-- HOLE 8 — sensitive data in a plaintext column.
CREATE TABLE public.musteriler (
  id uuid PRIMARY KEY,
  ad text NOT NULL,
  tc_kimlik text,
  iban text
);
