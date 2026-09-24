import type { StaticContext } from "./rule.js";
import { callsHelper, collectHelperlar } from "./kesif.js";

/**
 * Discovers a project's OWN auth helpers.
 *
 * The identity rules used to look at a fixed list of names: `getServerSession`,
 * `currentUser`, `requireAuth`… Real projects name their own —
 * `getPanelActor`, `adminActor`, `resolveViewer` — and because the fixed list
 * did not know them, fully protected routes were flagged as "no auth check".
 * In one project this was two of seven "high" findings.
 *
 * The fix is not a longer list: we decide whether a function is an auth helper
 * FROM ITS BODY. Any function that reads a session, cookie or token and returns
 * an identity counts as an auth check for the routes that call it.
 *
 * The engine lives in core/kesif.ts; this file is the identity expertise.
 */

/** Signals that a function body does identity work. */
const KIMLIK_SINYALI =
  /(cookies\s*\(|headers\s*\(|headers\.get\s*\(\s*['"`]cookie|\breq\.cookies\b|cookies\.get\s*\(|getServerSession|currentUser|\bsession\b|jwt\.verify|verifyToken|decodeToken|authorization|bearer|clerk|supabase[\s\S]{0,40}\.auth\.|getToken\s*\()/i;

/** Naming that suggests it returns an identity.
 *
 * client/tenant/workspace/org are included: in multi-tenant SaaS a "resolve the
 * active customer" resolver (e.g. resolveActiveClientId) IS effectively an auth
 * GATE — it derives the tenant from a cookie or session and returns 401/empty
 * otherwise. SAFE because the body signal (reading a cookie or session) is still
 * required; only client resolvers that really read identity count, not
 * display-only helpers such as `getClientName`. */
// `admin|owner|role|guard|gate|yonetici`: gercekte en yaygin kapi adlari bunlar
// (`requireAdmin`, `getAdmin`, `ensureOwner`, `requireRole`). Listede olmadiklari
// icin TAM KORUMALI kod "auth kontrolu yok" diye isaretlenebiliyordu. Govde
// sinyali (cerez/oturum okuma) yine sart oldugundan bu genisleme yanlis pozitif
// degil, yanlis NEGATIF duzeltmesidir.
const KIMLIK_ADI = /^(get|require|resolve|current|ensure|assert|fetch|load|read)?\s*\w*(actor|user|session|identity|principal|viewer|account|auth|member|subject|caller|client|tenant|workspace|org|admin|owner|role|guard|gate|yonetici)\w*$/i;

const SPEC = { ad: KIMLIK_ADI, sinyal: KIMLIK_SINYALI } as const;

/** The names of the project's auth helpers. */
export function collectAuthHelpers(ctx: StaticContext): Set<string> {
  return collectHelperlar(ctx, SPEC);
}

/** Does the given content call one of the project's auth helpers? */
export function callsAuthHelper(content: string, helpers: Set<string>): boolean {
  return callsHelper(content, helpers);
}
