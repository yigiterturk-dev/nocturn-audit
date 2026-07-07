import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A10 — SSRF: kullanıcı girdisiyle sunucu tarafı fetch/istek, allowlist yok.
 */

// fetch/axios/got/http.request'e değişken URL geçilmesi
const SERVER_REQUEST =
  /\b(fetch|axios|axios\.get|axios\.post|got|http\.request|https\.request|request)\s*\(\s*([`'"]?\$?\{?[A-Za-z_]\w*|`[^`]*\$\{)/;

const INPUT_SOURCE =
  /(req\.|params|searchParams|query\.|body|input|formData|request\.|url\s*=|targetUrl|remoteUrl|imageUrl|webhookUrl|callbackUrl)/i;

const ALLOWLIST_HINT =
  /(allowlist|allowList|whitelist|isAllowed|ALLOWED_HOSTS|new URL[\s\S]{0,60}(host|hostname)[\s\S]{0,40}(includes|===|==|match))/i;

export const ssrf: StaticRule = {
  id: "a10-ssrf-user-controlled-request",
  title: "Olası SSRF: kullanıcı kontrollü sunucu isteği",
  owasp: "A10:2021-Server-Side Request Forgery",
  severity: "medium",
  kind: "static",
  // Paternsel tespit (girdinin gerçekten dış URL'e aktığı elle doğrulanmalı).
  confidence: "olası",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      const f = file.replace(/\\/g, "/");
      // sunucu tarafı: api/route/actions/lib
      if (!/(app\/|pages\/api\/|route\.|actions?\.|lib\/|server)/.test(f)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      const fileHasAllowlist = ALLOWLIST_HINT.test(content);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!SERVER_REQUEST.test(raw) && !/\bfetch\s*\(\s*\w/.test(raw)) continue;
        const around = lines.slice(Math.max(0, i - 6), i + 3).join("\n");
        if (!INPUT_SOURCE.test(around)) continue;
        if (fileHasAllowlist) continue;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "medium",
          description:
            "Sunucu tarafında kullanıcı girdisinden türeyen bir URL'e istek yapılıyor ve host allowlist/doğrulama izi yok. Saldırgan iç servislere (169.254.169.254, localhost, iç ağ) istek yaptırabilir (SSRF).",
          evidence: [fileEvidence(file, i + 1, raw)],
          remediation:
            "Hedef URL'i katı bir host allowlist ile doğrulayın; şema/host'u kısıtlayın, iç IP aralıklarını (metadata, localhost, private) reddedin, yönlendirmeleri sınırlayın.",
        });
        break;
      }
    }
    return findings;
  },
};
