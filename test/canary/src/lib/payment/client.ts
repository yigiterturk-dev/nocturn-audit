// HOLE 23 — a secret leaked to the client (a NEXT_PUBLIC_ prefix on a secret value).
export const ODEME_GIZLI = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;

// HOLE 24 — a paid API called in an UNBOUNDED loop: however many listings exist,
// that many requests go out, with no budget check.
export async function tumIlanlariZenginlestir(ilanlar: string[]) {
  const sonuclar = [];
  for (const ilan of ilanlar) {
    const cevap = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [{ role: "user", content: ilan }],
    });
    sonuclar.push(cevap);
  }
  return sonuclar;
}

declare const openai: any;
