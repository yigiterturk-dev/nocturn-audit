-- HOLE 33 — a ONE-SIDED immutability guard: updates are rejected but
-- SİLME serbest. Değiştirilemeyen bir kaydı silmek de değiştirmektir.
CREATE FUNCTION yevmiye_reddet() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Yevmiye defteri değiştirilemez';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER yevmiye_immutable
  BEFORE UPDATE ON yevmiye_defteri
  FOR EACH ROW
  EXECUTE FUNCTION yevmiye_reddet();
