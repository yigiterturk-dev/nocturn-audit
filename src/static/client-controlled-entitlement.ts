import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";
import { kapsamdaTanim, lineNo, ts } from "../core/ast.js";

/**
 * A01 — client-controlled entitlement.
 *
 * A value that arrived from the client is written straight into a field that
 * decides what the account is ALLOWED to do (plan, packs, role, permissions,
 * credits). The account then grants itself whatever it asked for.
 *
 * WHY THIS RULE EXISTS (Bridal Stack, 2026-09-09):
 * The onboarding action took the pack list from the browser and wrote it to
 * `tenant.packs` with no price check. The ready-made presets on that screen
 * included paid modules, so anyone finishing setup unlocked $116/month of
 * product for free — and since the trial end date was never set anywhere, it
 * never expired. The paid path (Stripe checkout) DID check `isPackSellable`;
 * the setup path did not. That is the shape this rule looks for: two writers
 * of the same entitlement field, only one of them guarded.
 *
 * The lesson generalises past that incident — every path that writes an
 * entitlement must pass the same filter, so the rule flags the WRITE, not the
 * screen it happens to sit behind.
 */

/**
 * Fields that decide what an account may do.
 *
 * Both spellings matter: `packs: value` and the shorthand `packs,`. The real
 * incident used the shorthand, and a rule that only saw the long form would
 * have stayed silent on the very case that produced it.
 */
const FIELD_NAMES =
  "packs|plan|planId|plan_id|role|roles|permissions|enabled_modules|enabledModules|entitlements|features|tier|subscription_tier|is_admin|isAdmin|isPro|credits|quota|limits";
// The shorthand can sit anywhere in the object literal — `packs,` at the end of
// its own line, but also `{ owner_id: userId, packs }` inline. The canary was
// written with the inline form and the first version of this regex missed it.
const ENTITLEMENT_FIELD = new RegExp(`(?:^|[{,])\\s*(?:${FIELD_NAMES})\\s*(?::|,|\\}|$)`);
const FIELD_ASSIGN = new RegExp(`(?:^|[{,])\\s*(?:${FIELD_NAMES})\\s*:`);
const FIELD_SHORTHAND = new RegExp(`(?:^|[{,])\\s*(${FIELD_NAMES})\\s*(?:,|\\}|$)`);

/** Values that arrive from the client. */
const USER_INPUT =
  /(req\.body|req\.json\(\)|request\.json\(\)|await\s+req\.|formData\.get|\bbody\.[a-zA-Z_]|\binput\.[a-zA-Z_]|\bpayload\.[a-zA-Z_]|searchParams\.get|nextUrl\.searchParams|\bparams\.[a-zA-Z_])/;

/** An ORM write — the value actually lands in storage. */
const ORM_WRITE = /\.(create|createMany|update|updateMany|upsert|save|insert)\s*\(/;

/**
 * Signals that the value was checked before being written. Deliberately broad:
 * a missed finding costs less than a rule nobody trusts.
 */
const GUARD = new RegExp(
  [
    // The value was priced before it was granted.
    "isPackSellable|monthlyPrice|calculateMonthlyPrice|priceId|price_id|stripe|checkout\\.sessions",
    // The caller's authority was checked.
    "hasPermission|roleAtLeast|requireRole|assertRole|normalizeRole|isAdmin\\(|canManage",
    // A fail-closed gate helper: requireStaffManager(), assertCan(), isPatron(), ...
    "require[A-Z]\\w*\\s*\\(|assert[A-Z]\\w*\\s*\\(|is(?:Patron|Owner|Admin|Manager|Staff|Authorized|Allowed)\\w*\\s*\\(",
    // The role was normalised through a server-side mapper.
    "normalize\\w*Role\\s*\\(|toRole\\s*\\(|parseRole\\s*\\(",
    // The value was verified cryptographically — signed session/token, not raw client input.
    "timingSafeEqual|jwt\\.verify|verifyToken|createHmac",
    // The value was TESTED against an allowlist — ASSIGNABLE_ROLES.includes(role).
    "[A-Z][A-Z0-9_]{2,}\\.(?:includes|has|indexOf)\\s*\\(",
    // Signed server-to-server input is not client input.
    "\\bwebhook\\b|signature",
  ].join("|"),
  "i",
);

/**
 * NOT a guard: merging the client's value with a server-side constant.
 *
 * The canary taught this. The real onboarding code read
 * `[...FREE_PACK_IDS, ...validPacks]`, and an earlier version of this rule
 * treated the `FREE_` constant as proof that the value had been filtered — so
 * it stayed silent on the exact file it was written for. Adding the free tier
 * to the client's list does not remove the client's list from it. A constant
 * only clears the write when it REPLACES the untrusted value, and that case is
 * already covered: there is no taint left to follow.
 */

export const clientControlledEntitlement: StaticRule = {
  id: "a01-client-controlled-entitlement",
  title: "Client-controlled entitlement written straight to storage",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  cwe: "CWE-639",
  kind: "static",
  // Reads files only; the check is structural, so no external precondition.
  requires: [],
  confidence: "likely",
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?|\.d\.ts$)/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      // The write and the input have to be in the same file for this to be measurable.
      if (!ORM_WRITE.test(content) || !USER_INPUT.test(content)) continue;

      const tree = ctx.ast(file);
      const lines = content.split(/\r?\n/);

      /**
       * Taint is FUNCTION scoped, not file scoped. A route file usually holds
       * both a public handler and an admin one; a file-wide set would let the
       * public handler's `body.role` condemn the admin handler's legitimate
       * `role:` write.
       */
      const kapsamdaZehirli = (
        lineIndex: number,
        ad: string,
        gorulen = new Set<string>(),
      ): boolean => {
        if (!tree || gorulen.has(ad) || gorulen.size > 4) return false;
        gorulen.add(ad);
        let hedef: ts.Node | null = null;
        const gez = (n: ts.Node): void => {
          if (hedef) return;
          if (ts.isIdentifier(n) && n.text === ad && lineNo(tree, n) === lineIndex + 1) hedef = n;
          else ts.forEachChild(n, gez);
        };
        gez(tree.source);
        if (!hedef) return false;
        const tanim = kapsamdaTanim(hedef, ad);
        if (!tanim?.initializer) return false;
        const init = tanim.initializer.getText(tree.source);
        // A guard on the derivation itself (a filter, a price check) clears it.
        if (GUARD.test(init)) return false;
        if (USER_INPUT.test(init)) return true;

        /**
         * FOLLOW THE CHAIN. The incident laundered the value through one
         * intermediate name: `packs` came from `validPacks`, and only THAT came
         * from `input.packs`. A single-step check saw a clean local variable and
         * reported nothing — the rule would have missed the bug it exists for.
         */
        const tanimSatiri = lineNo(tree, tanim);
        for (const m of init.matchAll(/[A-Za-z_$][\w$]*/g)) {
          const parca = m[0];
          if (parca === ad) continue;
          if (kapsamdaZehirli(tanimSatiri - 1, parca, gorulen)) return true;
        }
        return false;
      };

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!ENTITLEMENT_FIELD.test(raw)) continue;

        const shorthand = !FIELD_ASSIGN.test(raw) ? FIELD_SHORTHAND.exec(raw)?.[1] : undefined;
        const value = shorthand
          ? shorthand
          : raw.slice(raw.indexOf(":", raw.search(FIELD_ASSIGN)) + 1);
        // A guard next to the write itself (ternary on a price, a server constant).
        if (GUARD.test(value)) continue;

        const directInput = USER_INPUT.test(value);
        const varAd = /^\s*([A-Za-z_$][\w$]*)\s*[,}]?\s*$/.exec(
          value.replace(/\s*\/\/.*$/, ""),
        )?.[1];
        const taintedVar = !directInput && !!varAd && kapsamdaZehirli(i, varAd);
        if (!directInput && !taintedVar) continue;

        /**
         * The gate is usually the FIRST thing in the handler, not the line above
         * the write. A 12-line window read `update: { role }` in a staff action
         * as unguarded even though the function opened with requireStaffManager()
         * and an ASSIGNABLE_ROLES allowlist. Scan from the start of the enclosing
         * function instead.
         */
        const fonksiyonBasi = (() => {
          for (let j = i; j >= 0; j--) {
            if (/^(export\s+)?(async\s+)?function\s|^\s*(export\s+)?const\s+\w+\s*=\s*(async\s*)?\(/.test(lines[j]))
              return j;
          }
          return Math.max(0, i - 12);
        })();
        const yakinBaglam = lines.slice(fonksiyonBasi, i + 3).join("\n");

        /**
         * A FAIL-CLOSED EXIT counts as a gate even when the helper has a name this
         * rule has never seen. Three of the first four field hits were guarded by
         * exactly this shape under a local name — isPatron(), assertCan() — and a
         * rule that only knows a fixed list of helper names would report all three.
         * What matters is not the name: it is that the function refuses to continue
         * unless the caller's role passes.
         */
        const KAPI =
          /\b(?:if|unless)\s*\([^)]*\b(role|roles|permission|permissions|yetki|izin|actor|member|session)\b[^)]*\)\s*(?:\{[^}]{0,120})?\s*(?:redirect|throw|return\s+(?:new\s+)?(?:NextResponse|Response)[^;]*\b(?:401|403)|return\s+null)/i;
        if (KAPI.test(yakinBaglam)) continue;
        if (GUARD.test(yakinBaglam)) continue;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "high",
          cwe: this.cwe,
          confidence: "likely",
          description:
            "A value that came from the client is written directly into a field that decides what the account is allowed to do (plan, packs, role, permissions). Whoever calls this endpoint chooses their own entitlement: paid modules unlock without payment, or a member promotes themselves. Check every writer of the field — the guarded path is usually the paid one, and the unguarded path is the setup or import screen next to it.",
          evidence: [fileEvidence(file, i + 1, raw.trim())],
          remediation:
            "Derive the entitlement on the server. Take the client value as a REQUEST only: grant the free tier, record what was asked for, and let the payment (or an admin with the right permission) decide the rest.",
          remediationCode:
            "// The selection is a request, not a payment.\n" +
            "const granted = FREE_PACK_IDS;\n" +
            "const requestedPaid = selected.filter((p) => PACKS[p].monthlyPrice > 0);\n" +
            "await prisma.tenant.create({ data: { packs: granted, settings: { requestedPaid } } });",
        });
      }
    }

    return findings;
  },
};
