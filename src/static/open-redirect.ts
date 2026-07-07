import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A01 — Açık yönlendirme (Open Redirect).
 *
 * Kullanıcı girdisinden (query/body/searchParams) gelen bir hedefin doğrulanmadan
 * redirect/location çağrısına verilmesi. Phishing ve OAuth token sızıntısına yol açar.
 */

const REDIRECT_CALL =
  /\b(redirect|res\.redirect|NextResponse\.redirect|Response\.redirect|location\.(?:href|assign|replace)|window\.location\s*=|location\s*=)\s*[\(=]/i;

const USER_INPUT =
  /(req\.query|req\.body|req\.params|request\.(?:query|body)|searchParams\.get|nextUrl\.searchParams|url\.searchParams\.get|getQuery|\bparams\.[a-zA-Z_]|\bquery\.[a-zA-Z_])/;

// Güvenli yönlendirme göstergeleri (varsa dosyada, false-positive'i azalt).
const VALIDATION =
  /startsWith\(\s*["'`]\/|allowed?(?:Hosts|Redirects|Origins|Paths)|allowlist|allow[_-]?list|isSafeRedirect|safeRedirect|\.origin\s*===|new URL\([^)]*\)[^\n]*\.(?:origin|hostname|host)/i;

export const openRedirect: StaticRule = {
  id: "a01-open-redirect",
  title: "Doğrulanmamış yönlendirme (open redirect)",
  owasp: "A01:2021-Broken Access Control",
  severity: "medium",
  cwe: "CWE-601",
  kind: "static",
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      // Dosyada açık bir doğrulama/allowlist varsa güvenli kabul et.
      if (VALIDATION.test(content)) continue;

      const lines = content.split(/\r?\n/);

      // Kullanıcı girdisinden türeyen "tainted" değişkenler.
      const tainted = new Set<string>();
      for (const raw of lines) {
        const dm = /\b(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*([^;]+)/.exec(raw);
        if (dm && USER_INPUT.test(dm[2])) tainted.add(dm[1]);
      }

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!REDIRECT_CALL.test(raw)) continue;

        const directInput = USER_INPUT.test(raw);
        const taintedArg =
          !directInput &&
          [...tainted].some((v) =>
            new RegExp(
              `(redirect|location[^\\n]*)[\\(=]\\s*(\`?\\$?\\{?)?${v}\\b`,
            ).test(raw),
          );

        if (directInput || taintedArg) {
          findings.push({
            ruleId: this.id,
            title: this.title,
            owasp: this.owasp,
            severity: "medium",
            cwe: this.cwe,
            description:
              "Yönlendirme hedefi doğrudan kullanıcı girdisinden (query/body/searchParams) alınıyor ve bir allowlist / same-origin kontrolü görülmüyor. Saldırgan kullanıcıyı harici bir siteye yönlendirebilir (phishing, OAuth token kaçırma).",
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation:
              "Yönlendirme hedefini yalnızca izinli yollara/originlere kısıtlayın: relatif yolları `startsWith('/')` ile doğrulayın veya sabit bir allowlist kullanın.",
            remediationCode:
              "const target = searchParams.get('next') ?? '/';\n" +
              "if (!target.startsWith('/') || target.startsWith('//')) return redirect('/');\n" +
              "return redirect(target);",
          });
        }
      }
    }
    return findings;
  },
};
