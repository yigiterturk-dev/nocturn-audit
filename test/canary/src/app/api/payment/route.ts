import { z } from "zod";

const semasi = z.object({ clientId: z.string(), tutar: z.number() });

// HOLE 34 — the authorisation check runs AFTER input VALIDATION: an unauthorised
// caller learns the shape of the system from the validation errors, and the
// expensive validation work is spent on an unauthorised request.
export async function POST(req: Request) {
  const govde = semasi.parse(await req.json());
  const izin = await checkPermission(req, govde.clientId);
  if (!izin) {
    return Response.json({ error: "Yetkisiz" }, { status: 403 });
  }
  return Response.json({ ok: true });
}

declare function checkPermission(r: Request, c: string): Promise<boolean>;
