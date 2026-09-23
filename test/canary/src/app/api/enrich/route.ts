import { tumIlanlariZenginlestir } from "../../../lib/payment/client";

// This route wires the paid loop into a LIVE chain: the rule rightly skips a
// dead module (code that never runs is not a billing risk), so the canary needs
// a real call path too.
export async function POST(req: Request) {
  const { ilanlar } = await req.json();
  const sonuc = await tumIlanlariZenginlestir(ilanlar);
  return Response.json(sonuc);
}
