// HOLE 31 — connection status derived FROM CONFIGURATION rather than from a real
// değil: env dolu diye "bağlı" deniyor. Token iptal edilmiş olabilir, panel
// yine "bağlı" gösterir.
export function entegrasyonDurumu() {
  if (!process.env.META_ACCESS_TOKEN) {
    return { durum: "bağlı değil", saglayici: "meta" };
  }
  return { durum: "bağlı", saglayici: "meta" };
}
