// HOLE 16 — unsigned webhook: a Stripe event handled without signature verification.
// (The real shape: the provider is known, the body is not read raw, no constructEvent.)
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_KEY ?? "");

export async function POST(req: Request) {
  const olay = (await req.json()) as Stripe.Event;
  if (olay.type === "checkout.session.completed") {
    await siparisiOnayla(olay.data.object.id);
  }
  return Response.json({ alindi: true });
}

declare function siparisiOnayla(id: string): Promise<void>;
