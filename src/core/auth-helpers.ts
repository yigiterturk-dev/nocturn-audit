import type { StaticContext } from "./rule.js";

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

// Dördüncü biçim (gerçek vaka — bir e-ticaret CRM projesi, 12 sahte HIGH): React cache()
// sarmalı. `export const getUserRole = cache(async () => ...)` yazan bir kapı,
// TANIM deseni `= cache(` değerini tanımadığı için keşfe HİÇ düşmüyor,
// callsAuthHelper başarısız oluyor ve TAM KORUMALI fonksiyon "auth yok"
// diye işaretleniyordu. Sarmalayıcı adı (cache/memo/unstable_cache) bilinçli
// olarak serbest: karar gövde sinyalinden gelir, adından değil.
const TANIM =
  /export\s+(?:async\s+)?function\s+(\w+)|(?:export\s+)?(?:async\s+)?function\s+(\w+)|(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(|(?:export\s+)?const\s+(\w+)\s*=\s*\w+\s*\(/g;

/**
 * The names of the project's auth helpers.
 *
 * Two passes: first the functions whose body carries a direct identity signal,
 * then the wrappers that call them (`adminActor()` → `getPanelActor()` →
 * cookie). A single pass would miss every helper wrapped one level deep — and in
 * real projects wrapping is the rule, not the exception.
 */
export function collectAuthHelpers(ctx: StaticContext): Set<string> {
  const dogrudan = new Set<string>();
  const govdeler = new Map<string, string>();

  for (const file of ctx.files) {
    if (!/\.(ts|tsx|js|jsx|mjs)$/.test(file)) continue;
    if (/\.(test|spec)\./.test(file)) continue;
    const content = ctx.read(file);
    if (!content) continue;

    TANIM.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TANIM.exec(content)) !== null) {
      const ad = m[1] || m[2] || m[3] || m[4];
      if (!ad || !KIMLIK_ADI.test(ad)) continue;
      const body = content.slice(m.index, m.index + 1200);
      govdeler.set(ad, body);
      if (KIMLIK_SINYALI.test(body)) dogrudan.add(ad);
    }
  }

  // Collect wrappers: a helper that calls a known helper counts too.
  // Three rounds, a reasonable chain depth; more is not seen in practice.
  const hepsi = new Set(dogrudan);
  for (let tur = 0; tur < 3; tur += 1) {
    for (const [ad, body] of govdeler) {
      if (hepsi.has(ad)) continue;
      for (const bilinen of hepsi) {
        if (new RegExp(`\\b${bilinen}\\s*\\(`).test(body)) {
          hepsi.add(ad);
          break;
        }
      }
    }
  }
  return hepsi;
}

/** Does the given content call one of the project's auth helpers? */
export function callsAuthHelper(content: string, helpers: Set<string>): boolean {
  for (const ad of helpers) {
    if (new RegExp(`\\b${ad}\\s*\\(`).test(content)) return true;
  }
  return false;
}
