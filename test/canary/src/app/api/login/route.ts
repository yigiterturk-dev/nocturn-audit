import { db, kullanicilar } from "../../../../db/schema";

// HOLE 21 — no rate limiting or brute-force protection on a sensitive endpoint (login).
// HOLE 22 — no security or audit logging on a sensitive endpoint.
export async function POST(req: Request) {
  const { email, parola } = await req.json();
  const kullanici = await db.select().from(kullanicilar).where(eq(kullanicilar.email, email));
  if (!kullanici || !(await dogrula(parola, kullanici.hash))) {
    return Response.json({ error: "Invalid email or password" }, { status: 401 });
  }
  return Response.json({ ok: true, token: imzala(kullanici.id) });
}

declare function dogrula(a: string, b: string): Promise<boolean>;
declare function imzala(id: string): string;
declare function eq(a: unknown, b: unknown): unknown;
