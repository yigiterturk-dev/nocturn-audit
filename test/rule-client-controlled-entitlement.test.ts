import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { clientControlledEntitlement } from "../src/static/client-controlled-entitlement.js";

const run = (files: Record<string, string>) =>
  clientControlledEntitlement.run(makeCtx(files)) as Array<{ severity: string }>;

/**
 * a01-client-controlled-entitlement
 *
 * The BAD fixture is the real incident, trimmed: Bridal Stack's onboarding
 * action wrote the browser's pack selection into `tenant.packs` with no price
 * check, so the setup screen handed out $116/month of paid modules for free.
 * The CLEAN fixtures are the two shapes that sit right next to it and ARE safe
 * — the same file's paid path, and a server-derived free tier.
 */
describe("a01-client-controlled-entitlement", () => {
  it("BAD: the pack selection from the browser is written to the tenant", () => {
    const f = run({
      "app/onboarding/actions.ts": `
export async function completeOnboarding(input: OnboardingInput) {
  const validPacks = (Array.isArray(input.packs) ? input.packs : [])
    .filter((p): p is PackId => typeof p === "string" && p in PACKS);
  const packs: PackId[] = [...new Set([...validPacks])];

  await prisma.tenant.create({
    data: {
      name: shopName,
      packs,
      plan: packs.length > 1 ? "starter" : "free",
    },
  });
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe("high");
  });

  it("BAD: a member sets their own role from the request body", () => {
    const f = run({
      "app/api/members/route.ts": `
export async function POST(req: Request) {
  const body = await req.json();
  await prisma.tenantMember.update({
    where: { id: body.id },
    data: { role: body.role },
  });
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });


  /**
   * CANARY — the field shape, not the imagined one.
   *
   * The first BAD fixture here was a trimmed version of the incident and it
   * PASSED while the real file still slipped through: the production line read
   * `[...FREE_PACK_IDS, ...validPacks]`, and the rule read that `FREE_`
   * constant as proof the value had been filtered. Merging a server constant
   * into the client's list does not remove the client's list. This test keeps
   * the real line so the hole cannot reopen.
   */
  it("CANARY: the client list merged with a server constant is still tainted", () => {
    const f = run({
      "app/onboarding/actions.ts": `
export async function completeOnboarding(input: OnboardingInput) {
  const validPacks = (Array.isArray(input.packs) ? input.packs : [])
    .filter((p): p is PackId => typeof p === "string" && p in PACKS);
  // Free packs are always on; the user gets them even if they forget to choose.
  const packs: PackId[] = [...new Set([...FREE_PACK_IDS, ...validPacks])];

  await prisma.tenant.create({
    data: { name: shopName, slug, owner_id: userId, packs },
  });
}`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("CLEAN: the paid path checks the price before granting", () => {
    const f = run({
      "app/api/stripe/checkout/route.ts": `
export async function POST(req: NextRequest) {
  const { packs } = await req.json();
  const sellable = packs.filter((p: PackId) => isPackSellable(p));
  const checkout = await stripe.checkout.sessions.create({ line_items: lineItems });
  await prisma.tenant.update({
    where: { id: tenant.id },
    data: { packs: sellable, plan: "starter" },
  });
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: the tier is derived on the server, not taken from the client", () => {
    const f = run({
      "app/api/auth/register/route.ts": `
export async function POST(req: Request) {
  const body = await req.json();
  await prisma.tenant.create({
    data: {
      name: body.shopName,
      packs: FREE_PACK_IDS,
      plan: "free",
    },
  });
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: an admin route guarded by a permission check", () => {
    const f = run({
      "app/api/admin/members/route.ts": `
export async function POST(req: Request) {
  const body = await req.json();
  if (!hasPermission(session.user.role, "staff.manage")) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }
  await prisma.tenantMember.update({
    where: { id: body.id },
    data: { role: body.role },
  });
}`,
    });
    expect(f.length).toBe(0);
  });


  /**
   * FIELD CLEANS — the first portfolio-wide run produced three hits and all three
   * were false positives. They are kept here verbatim-ish: a rule that reports a
   * guarded staff screen is a rule people learn to ignore, and an ignored rule
   * protects nothing. Each one is guarded by a shape, not by a name this rule
   * could have hard-coded.
   */
  it("FIELD CLEAN: fail-closed gate under a local name (isPatron)", () => {
    const f = run({
      "app/staff/actions.ts": `
export async function inviteStaff(formData: FormData) {
  const role = await getUserRole();
  if (!isPatron(role)) redirect("/dashboard");

  const staffRole = normalizeStaffRole(String(formData.get("role") || "calisan").trim());
  await admin.from("user_roles").upsert({
    user_id: created.user.id,
    role: staffRole,
    permissions: staffRole === "calisan" ? ["dashboard"] : null,
  });
}`,
    });
    expect(f.length).toBe(0);
  });

  it("FIELD CLEAN: the actor's role comes from the session, not the request", () => {
    const f = run({
      "lib/data/team.ts": `
export async function inviteMember(businessId: string, actorRole: string, input: { role: Role }) {
  assertCan(actorRole, "ekip");
  if (input.role === "sahip") throw new Error("Sahip rolu davetle verilemez.");
  await db.insert(schema.users).values({
    businessId,
    role: input.role,
  });
}`,
    });
    expect(f.length).toBe(0);
  });

  it("FIELD CLEAN: role read from a cryptographically verified token", () => {
    const f = run({
      "src/lib/auth.ts": `
export function readSession(cookie: string) {
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) return null;
  const payload = JSON.parse(Buffer.from(data, "base64url").toString());
  const role: TeamRole = payload.role === "sales" ? "sales" : "owner";
  return { userId: payload.userId, role };
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a file with no storage write is not measured", () => {
    const f = run({
      "components/plan-picker.tsx": `
export function PlanPicker({ input }: Props) {
  const packs = input.packs;
  return <div data-plan={packs}>{packs.join(", ")}</div>;
}`,
    });
    expect(f.length).toBe(0);
  });
});
