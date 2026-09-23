import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";
import { collectAuthHelpers } from "../core/auth-helpers.js";

/**
 * A01 — the PAGE and the API use different auth paths.
 *
 * A server-rendered page runs its own query and CHOOSES its own auth call. The
 * API being right does not make the page right — and tests are usually written
 * against the API, so the divergence never shows up.
 *
 * Real case: in a tenant portal the page called `getPanelActor()`, a function
 * that returns null for a non-staff session. The result: a signed-in tenant
 * visiting their own portal was 307'd to the login screen. Because every portal
 * test went through `/api/management`, the page had never been opened; the bug
 * had nowhere to surface.
 *
 * The rule looks for this: API routes use N auth helpers TOGETHER while the page
 * in the same area calls only some of them.
 */

const isPage = (file: string): boolean =>
  /(^|\/)(app|src\/app)\/(?:.*\/)?(page|layout)\.(tsx|jsx)$/.test(file.replace(/\\/g, "/"));

const isApiRoute = (file: string): boolean =>
  /(^|\/)app\/.*\/route\.(ts|js)$/.test(file.replace(/\\/g, "/"))
  || /(^|\/)pages\/api\/.*\.(ts|js)$/.test(file.replace(/\\/g, "/"));

/** Auth helpers called in the content. */
function cagrilanlar(content: string, yardimcilar: Set<string>): Set<string> {
  const bulunan = new Set<string>();
  for (const ad of yardimcilar) {
    if (new RegExp(`\\b${ad}\\s*\\(`).test(content)) bulunan.add(ad);
  }
  return bulunan;
}

/**
 * Does the page's PATH say who it is for?
 *
 * The first version expected every page to match the API's widest auth set and
 * produced nine findings, most of them wrong. A STAFF page legitimately uses
 * only the staff helper; that is correct design, not a bug.
 *
 * The real signal is the page's own identity: a `/resident` page is for the
 * TENANT. If it does not call the helper that serves tenants, the audience it
 * was built for cannot open it.
 */
const OZNELER: Array<{ ad: string; path: RegExp; yardimci: RegExp }> = [
  { ad: "tenant", path: /\/(resident|tenant|kiraci)(\/|$)/i, yardimci: /(portal|resident|tenant|kiraci)/i },
  { ad: "owner", path: /\/(owner|landlord|sahip|malik)(\/|$)/i, yardimci: /(portal|owner|sahip|malik)/i },
  { ad: "customer", path: /\/(customer|client|musteri)(\/|$)/i, yardimci: /(portal|customer|client|musteri)/i },
  { ad: "portal user", path: /\/portal(\/|$)/i, yardimci: /portal/i },
];

export const pageApiAuthDivergence: StaticRule = {
  id: "int-page-api-auth-divergence",
  title: "The page uses a narrower auth path than its API",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx: StaticContext): Finding[] {
    const yardimcilar = collectAuthHelpers(ctx);
    if (yardimcilar.size < 2) return [];

    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!isPage(file)) continue;
      const path = file.replace(/\\/g, "/");
      const ozne = OZNELER.find((o) => o.path.test(path));
      if (!ozne) continue;

      const content = ctx.read(file);
      if (!content) continue;
      const kume = cagrilanlar(content, yardimcilar);
      // A page that calls no auth at all may be public; not this rule's subject.
      if (!kume.size) continue;

      // ROL KAPILI SAYFA = PERSONEL YÜZEYİ (gerçek vaka, 2026-09-22 —
      // bir e-ticaret CRM projesi app/basit/musteri, 1 FP): yol "/musteri" içeriyor diye
      // sayfa müşteri portalı DEĞİLDİR — personelin müşteri LİSTESİDİR. Sayfa
      // rol kapısı çağırıyorsa (getUserRole/isPatron/rol denetimi) kitlesi
      // personeldir; müşteri/tenant/owner öznesi uygulanmaz. Yol adından
      // kitle çıkarsamak yalnız portal desenlerinde güvenilirdir.
      const rolKapili =
        /\b(getUserRole|isPatron|isYonetim|requireRole|hasRole|yetkiKontrol)\s*\(/.test(content);
      if (rolKapili && ozne.ad !== "portal user") continue;

      // Is there a helper serving this subject, and does the page call it?
      const ozneninYardimcilari = [...yardimcilar].filter((ad) => ozne.yardimci.test(ad));
      if (!ozneninYardimcilari.length) continue;
      if (ozneninYardimcilari.some((ad) => kume.has(ad))) continue;

      // Is there a route using this subject on the API side? If so the divergence is real.
      const rota = ctx.files.find((f) => {
        if (!isApiRoute(f)) return false;
        const routeContent = ctx.read(f) || "";
        return ozneninYardimcilari.some((ad) => new RegExp(`\\b${ad}\\s*\\(`).test(routeContent));
      });
      if (!rota) continue;

      findings.push({
        ruleId: "int-page-api-auth-divergence",
        title: "The page never calls the auth path of the audience it serves",
        owasp: "A01:2021-Broken Access Control",
        severity: "high",
        confidence: "likely",
        description:
          `By its path, \`${file}\` serves the ${ozne.ad}, yet for identity it only calls ` +
          `${[...kume].join(", ")}. The helper that serves a ${ozne.ad} session, ` +
          `${ozneninYardimcilari.join(", ")}, is never called — even though \`${rota}\` uses it. ` +
          `As a result a signed-in ${ozne.ad} cannot open this page. If the tests go through the API, ` +
          "this never shows up.",
        evidence: [fileEvidence(file, 1, [...kume].join(", "))],
        remediation:
          `Have the page call ${ozneninYardimcilari.join(" or ")}. Then write a test that ACTUALLY opens ` +
          "the page with that session type and asserts a 200 — an API that covers a case does not mean " +
          "the page covers it.",
      });
    }
    return findings;
  }
};
