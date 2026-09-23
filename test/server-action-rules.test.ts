import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { serverActionAuthMissing } from "../src/static/server-action-auth-missing.js";

describe("A01 — server action yetki kapısı", () => {
  it("BAD: kapısız server action DB'ye yazıyor → bulgu", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "lib/actions.ts":
        `"use server";\n` +
        `import { db } from "@/db";\n` +
        `export async function silHepsi(id: string) {\n` +
        `  await db.delete(tablo).where(eq(tablo.id, id));\n}`,
    }));
    expect(f.length).toBe(1);
  });

  it("BAD: kiracı kapsamı dışı (service_role) + kapısız → HIGH", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "lib/admin/actions.ts":
        `"use server";\n` +
        `const client = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\n` +
        `export async function tumKiracilar() {\n` +
        `  return client.from("businesses").select("*");\n}`,
    }));
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });

  it("CLEAN: kendi kapısı olan action bulgu DEĞİL", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "lib/guard.ts":
        `export async function requireAdmin() {\n` +
        `  const session = await getSession(); if (!session) throw new Error("yok");\n` +
        `  return session;\n}`,
      "lib/actions.ts":
        `"use server";\n` +
        `import { requireAdmin } from "./guard";\n` +
        `import { db } from "@/db";\n` +
        `export async function sil(id: string) {\n` +
        `  await requireAdmin();\n  await db.delete(t).where(eq(t.id, id));\n}`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: DELEGASYON — kapı çağrılan veri modülünde (bir rezervasyon SaaS deseni)", () => {
    // actions.ts kararı vermiyor, data.ts'e delege ediyor. Tek kapı = doğru desen;
    // yalnız action dosyasına bakan bir kural bunu yanlışlıkla suçlardı.
    const f = serverActionAuthMissing.run(makeCtx({
      "lib/admin/guard.ts":
        `export async function requireAdmin() {\n` +
        `  const session = await getLiveSession(); if (!session) throw new Error("Yetkisiz.");\n` +
        `  return session;\n}`,
      "lib/admin/data.ts":
        `import { requireAdmin } from "./guard";\n` +
        `import { db } from "@/db";\n` +
        `export async function activateSubscription(o) {\n` +
        `  const admin = await requireAdmin();\n  await db.update(subs).set(o);\n}`,
      "lib/admin/actions.ts":
        `"use server";\n` +
        `import { activateSubscription } from "./data";\n` +
        `export async function activateSubscriptionAction(input) {\n` +
        `  return activateSubscription(input);\n}`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: DB'ye dokunmayan server action bulgu DEĞİL", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "lib/actions.ts":
        `"use server";\n` +
        `export async function bicimlendir(x: string) { return x.trim().toUpperCase(); }`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: 'use server' olmayan dosya bu kuralın konusu değil", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "lib/data.ts": `import { db } from "@/db";\nexport async function hepsi() { return db.query.x.findMany(); }`,
    }));
    expect(f.length).toBe(0);
  });
});

describe("A01 — kimlik ÖNCESİ akışlar bu kuralın konusu değil", () => {
  it("CLEAN: parola sıfırlama action'ı bulgu DEĞİL (stackcrm gerçek vakası)", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "app/(auth)/forgot-password/actions.ts":
        `"use server";\n` +
        `import { prisma } from "@/lib/prisma";\n` +
        `export async function requestPasswordReset(formData: FormData) {\n` +
        `  const user = await prisma.user.findUnique({ where: { email } });\n` +
        `  await prisma.passwordResetToken.create({ data: { token_hash: hash } });\n}`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: giriş action'ı bulgu DEĞİL", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "app/giris/actions.ts":
        `"use server";\n` +
        `import { db } from "@/db";\n` +
        `export async function signIn(fd: FormData) {\n` +
        `  const u = await db.query.users.findFirst();\n  return u;\n}`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: tek kullanımlık jeton doğrulayan action bulgu DEĞİL", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "lib/kabul.ts":
        `"use server";\n` +
        `import { db } from "@/db";\n` +
        `export async function kabulEt(t: string) {\n` +
        `  const kayit = await db.query.davet.findUnique({ where: { token_hash: sha(t) } });\n` +
        `  if (!kayit || kayit.expires_at < new Date()) throw new Error("gecersiz");\n}`,
    }));
    expect(f.length).toBe(0);
  });

  it("BAD: panel action'ı hâlâ yakalanır (muafiyet fazla geniş değil)", () => {
    const f = serverActionAuthMissing.run(makeCtx({
      "app/panel/actions.ts":
        `"use server";\n` +
        `import { db } from "@/db";\n` +
        `export async function fiyatGuncelle(id: string, fiyat: number) {\n` +
        `  await db.update(urun).set({ fiyat }).where(eq(urun.id, id));\n}`,
    }));
    expect(f.length).toBe(1);
  });
});
