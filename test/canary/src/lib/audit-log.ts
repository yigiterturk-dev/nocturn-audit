// HOLE — personal data written to logs in the clear: email and phone in journald,
// sitting in plaintext in error tracking and on support screens.
export function siparisiIsle(siparis: { eposta: string; telefon: string; id: string }) {
  console.log(`Sipariş alındı: ${siparis.id} — ${siparis.eposta} / ${siparis.telefon}`);
  return { ok: true };
}
