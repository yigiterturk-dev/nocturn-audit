-- HOLE — special-category personal data: health information in a plaintext column.
CREATE TABLE hasta_kayitlari (
  id uuid PRIMARY KEY,
  diagnosis text,
  kan_grubu text,
  engelli boolean
);
