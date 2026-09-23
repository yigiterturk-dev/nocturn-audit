// HOLE — the test schema was copied from production BY HAND: when the production schema changes this
// copy drifts silently and the tests keep verifying the wrong schema.
export const testSemasi = `
CREATE TABLE kullanicilar (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  ad text
);
`;
