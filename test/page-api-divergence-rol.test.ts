import { describe, it, expect } from "vitest";
import { pageApiAuthDivergence } from "../src/integrity/page-api-auth-divergence.js";
import { makeCtx } from "./helpers.js";

const run = (files: Record<string, string>) => pageApiAuthDivergence.run(makeCtx(files));

describe("int-page-api-auth-divergence — rol kapılı sayfa ayrımı", () => {
  it("ROL kapılı personel sayfası müşteri-portal öznesiyle işaretlenmez (gerçek vaka: bir e-ticaret CRM projesi basit/musteri)", async () => {
    const f = await run({
      "lib/role.ts": `export async function getUserRole() {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  return user ? "patron" : null;\n}\nexport function isPatron(role: string) { return role === "patron"; }`,
      "lib/supabase/server.ts": `export async function getUser() {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  return user;\n}`,
      "app/basit/musteri/page.tsx": `import { getUser } from "@/lib/supabase/server";\nimport { getUserRole, isPatron } from "@/lib/role";\nexport default async function Page() {\n  const user = await getUser();\n  const role = await getUserRole();\n  if (!isPatron(role)) redirect("/");\n  return <div>müşteri sihirbazı</div>;\n}`,
      "app/api/musteri-portal/route.ts": `import { getMusteriOturumu } from "@/lib/role";\nexport async function GET() { return getMusteriOturumu(); }`,
    });
    expect(f).toHaveLength(0);
  });

  it("gerçek portal sapması hâlâ yakalanır: sayfa öznenin helper'ını hiç çağırmıyor", async () => {
    const f = await run({
      "lib/supabase/server.ts": `export async function getUser() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  return user;
}`,
      "lib/portal.ts": `export async function getPortalSession() {\n  const c = await cookies();\n  return c.get("portal")?.value ?? null;\n}`,
      "app/musteri/page.tsx": `import { getUser } from "@/lib/supabase/server";\nexport default async function Page() {\n  const user = await getUser();\n  return <div>{user?.email}</div>;\n}`,
      "app/api/musteri/route.ts": `import { getPortalSession } from "@/lib/portal";\nexport async function GET() { return getPortalSession(); }`,
    });
    // sayfa getUser çağırıyor, getPortalSession'ı hiç — divergence bulgusu beklenir
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});
