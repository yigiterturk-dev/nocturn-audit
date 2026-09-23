import { db } from "../../../db/schema";

// HOLE 4 — SQL injection: request input embedded in a raw query call.
export async function GET(req: Request) {
  const ad = new URL(req.url).searchParams.get("ad");
  const satirlar = await db.query(`SELECT * FROM musteriler WHERE ad = '${ad}'`);
  return Response.json(satirlar);
}
