import { db, oturumlar, uyeler } from "../db/schema";

// HOLE 32 — access is revoked but open SESSIONS stay alive: the account is disabled
// alive, and whoever holds the cookie keeps browsing.
export async function deactivateUser(uyeId: string) {
  await db.update(uyeler).set({ aktif: false }).where(eq(uyeler.id, uyeId));
  return { ok: true };
}

export async function resetPassword(uyeId: string, yeni: string) {
  await db.update(uyeler).set({ hash: await ozetle(yeni) }).where(eq(uyeler.id, uyeId));
  return { ok: true };
}

declare function eq(a: unknown, b: unknown): unknown;
declare function ozetle(p: string): Promise<string>;
