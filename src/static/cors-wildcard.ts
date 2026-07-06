import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A05 — CORS yanlış yapılandırması: Access-Control-Allow-Origin: *
 * özellikle Allow-Credentials: true ile birlikte.
 */

const ACAO_WILDCARD =
  /Access-Control-Allow-Origin["'\s:=,]+\*/i;
const ACAC_TRUE =
  /Access-Control-Allow-Credentials["'\s:=,]+(true|['"]true['"])/i;
// origin'i istekten yansıtma (dinamik güvensiz allowlist)
const ORIGIN_REFLECT =
  /Access-Control-Allow-Origin["'\s:=,]+[^*\n]{0,40}(req\.headers|request\.headers|origin)/i;

export const corsWildcard: StaticRule = {
  id: "a05-cors-misconfiguration",
  title: "Güvensiz CORS yapılandırması",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      const content = ctx.read(file);
      if (!content) continue;
      const wildcard = ACAO_WILDCARD.test(content);
      const credentials = ACAC_TRUE.test(content);
      const reflect = ORIGIN_REFLECT.test(content);
      if (!wildcard && !reflect) continue;

      const lines = content.split(/\r?\n/);
      let line = 1;
      let snippet = "";
      for (let i = 0; i < lines.length; i++) {
        if (
          ACAO_WILDCARD.test(lines[i]) ||
          ORIGIN_REFLECT.test(lines[i])
        ) {
          line = i + 1;
          snippet = lines[i];
          break;
        }
      }

      const severity: "high" | "medium" = credentials || reflect ? "high" : "medium";
      findings.push({
        ruleId: this.id,
        title: reflect
          ? "CORS origin isteği geri yansıtıyor"
          : credentials
            ? "CORS: wildcard origin + credentials"
            : "CORS wildcard origin (*)",
        owasp: this.owasp,
        severity,
        description: reflect
          ? "Access-Control-Allow-Origin isteğin Origin başlığını doğrudan yansıtıyor. Bu, credentials ile birlikte her siteye kimlikli erişim açar."
          : credentials
            ? "Access-Control-Allow-Origin: * ile Allow-Credentials: true birlikte kullanılamaz/güvensizdir; kimlikli cross-origin erişim riski."
            : "Access-Control-Allow-Origin: * tüm origin'lere açık. Hassas API'ler için origin allowlist gerekir.",
        evidence: [fileEvidence(file, line, snippet || "CORS *")],
        remediation:
          "Origin'i katı bir allowlist ile doğrulayın; credentials gerekiyorsa wildcard kullanmayın, izinli origin'i açıkça yansıtın ve listeye alın.",
      });
    }
    return findings;
  },
};
