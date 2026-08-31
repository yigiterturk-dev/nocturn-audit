import { cookies } from "next/headers";
import { db, kullanicilar } from "../../../db/schema";

// HOLE 1 — no auth: an unauthenticated route that writes to the database.
// HOLE 2 — CSRF: a cookie session with a FORM body (a cross-site form can trigger it).
// HOLE 3 — mass assignment: form data spread straight into the database.
export async function POST(req: Request) {
  const oturum = cookies();
  const form = await req.formData();
  const kayit = Object.fromEntries(form);
  await db.insert(kullanicilar).values({ ...kayit });
  return Response.json({ ok: true });
}
