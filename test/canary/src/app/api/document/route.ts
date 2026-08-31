import { db, belgeler } from "../../../../db/schema";

// HOLE — IDOR: an id from the request goes straight into a single-record query, with no ownership
// filter. Another customer's document can be read.
export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  const belge = await db.select().from(belgeler).eq("id", id).single();
  return Response.json(belge);
}
