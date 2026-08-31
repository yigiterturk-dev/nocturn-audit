import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A05 — CORS misconfiguration: Access-Control-Allow-Origin: *
 * especially together with Allow-Credentials: true.
 */

const ACAO_WILDCARD =
  /Access-Control-Allow-Origin["'\s:=,]+\*/i;
const ACAC_TRUE =
  /Access-Control-Allow-Credentials["'\s:=,]+(true|['"]true['"])/i;
// reflecting the origin from the request (a dynamic, unsafe allowlist)
const ORIGIN_REFLECT =
  /Access-Control-Allow-Origin["'\s:=,]+[^*\n]{0,40}(req\.headers|request\.headers|origin)/i;

export const corsWildcard: StaticRule = {
  id: "a05-cors-misconfiguration",
  title: "Insecure CORS configuration",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      const content = ctx.read(file);
      if (!content) continue;
      const wildcard = ACAO_WILDCARD.test(content);
      const credentials = ACAC_TRUE.test(content);
      let reflect = ORIGIN_REFLECT.test(content);

      // ALLOWLIST-GUARDED REFLECTION IS SAFE: when the origin is reflected only
      // AFTER passing an allowlist check (ALLOWED_ORIGINS.includes(origin) /
      // whitelist / origin===), this is the correct CORS pattern, not a hole.
      // (Delta server.ts: ALLOWED_ORIGINS.includes(origin) → FP'ydi.)
      const allowlistGuard =
        /ALLOWED_ORIGINS|allowedOrigins|allowlist|allow[_-]?list|whitelist|\.includes\s*\(\s*origin|\borigin\s*===|origins?\.(has|includes)\s*\(|isAllowedOrigin|corsOrigins/i.test(content);
      if (reflect && allowlistGuard) reflect = false;
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
          ? "CORS reflects the request origin"
          : credentials
            ? "CORS: wildcard origin + credentials"
            : "CORS wildcard origin (*)",
        owasp: this.owasp,
        severity,
        description: reflect
          ? "Access-Control-Allow-Origin echoes the request's Origin header. Combined with credentials this grants authenticated access to every site."
          : credentials
            ? "Access-Control-Allow-Origin: * cannot be combined safely with Allow-Credentials: true — it risks authenticated cross-origin access."
            : "Access-Control-Allow-Origin: * is open to every origin. Sensitive APIs need an origin allowlist.",
        evidence: [fileEvidence(file, line, snippet || "CORS *")],
        remediation:
          "Validate the origin against a strict allowlist. If you need credentials, never use a wildcard — echo only origins that are on the list.",
      });
    }
    return findings;
  },
};
