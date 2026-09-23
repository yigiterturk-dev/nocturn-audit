import { describe, it, expect } from "vitest";
import { collectAuthHelpers } from "../src/core/auth-helpers.js";
import { makeCtx } from "./helpers.js";

/**
 * GERÇEK VAKA (bir e-ticaret CRM projesi, 12 sahte HIGH, 2026-09-22): React `cache()`
 * sarmallı kapılar TANIM desenine düşmüyordu, callsAuthHelper başarısız
 * oluyor ve tam korumalı fonksiyonlar "auth yok" diye işaretleniyordu.
 */
describe("auth helper keşfi — cache() sarmalı", () => {
  it("export const X = cache(async () => ...) deseni keşfedilir", () => {
    const ctx = makeCtx({
      "lib/role.ts": `import { createClient, getUser } from "@/lib/supabase/server";\nexport const getUserRoleData = cache(async (): Promise<UserRoleData> => {\n  const supabase = await createClient();\n  const user = await getUser();\n  if (!user) return null;\n  return supabase.from("user_roles").select("*").maybeSingle();\n});\nexport async function getUserRole(): Promise<UserRole> {\n  const { role } = await getUserRoleData();\n  return role;\n}`,
      "lib/supabase/server.ts": `export async function getUser() {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  return user;\n}`,
    });
    const helpers = collectAuthHelpers(ctx);
    expect(helpers.has("getUser")).toBe(true);
    expect(helpers.has("getUserRoleData")).toBe(true); // cache() sarmalı artık görünür
    expect(helpers.has("getUserRole")).toBe(true);      // sarmalayıcı zinciri bağlanır
  });

  it("keşif adından değil GÖVDENİN sinyalinden karar verir — görüntü helper'ı seçmez", () => {
    const ctx = makeCtx({
      "lib/display.ts": `export const getClientName = memo(async (id: string) => {\n  return "Ali";\n});`,
    });
    expect(collectAuthHelpers(ctx).has("getClientName")).toBe(false);
  });
});
