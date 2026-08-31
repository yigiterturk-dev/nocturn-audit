// HOLE 13 — open redirect: the target goes into Location without validation.
export async function GET(req: Request) {
  const nereye = new URL(req.url).searchParams.get("next") ?? "/";
  return Response.redirect(nereye, 302);
}
