import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A01 — the authorisation check runs AFTER input validation.
 *
 * Two consequences. First: someone with no write permission learns the shape of
 * the API before being rejected. Second, and more insidious: the gate's
 * existence can only be tested by constructing a valid body for every resource,
 * which in practice means it is never tested.
 */
const DOGRULAMA = /\b(safeParse|\.parse\(|validate\(|schema\.\w+\()/;
const YETKI = /\b(canManage|can[A-Z]\w*|authorize|checkPermission|requireRole|hasPermission|yetki)\w*\(/;

const isApiRoute = (file: string): boolean =>
  /(^|\/)app\/.*\/route\.(ts|js)$/.test(file.replace(/\\/g, "/")) ||
  /(^|\/)pages\/api\/.*\.(ts|js)$/.test(file.replace(/\\/g, "/"));

export const permissionAfterValidation: StaticRule = {
  id: "int-permission-after-validation",
  title: "The authorisation check runs after input validation",
  owasp: "A01:2021-Broken Access Control",
  severity: "low",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!isApiRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      for (const body of content.split(/export async function (?=POST|PATCH|PUT|DELETE)/).slice(1)) {
        const dogrulama = body.search(DOGRULAMA);
        const yetki = body.search(YETKI);
        if (dogrulama < 0 || yetki < 0 || yetki < dogrulama) continue;

        const line = content.slice(0, content.indexOf(body)).split("\n").length;
        findings.push({
          ruleId: "int-permission-after-validation",
          title: "The authorisation check runs after input validation",
          owasp: "A01:2021-Broken Access Control",
          severity: "low",
          confidence: "likely",
          description:
            `In \`${file}\` the authorisation check comes after input validation. An unauthorised caller ` +
            "learns the schema first, and the gate itself cannot be tested without constructing a valid body.",
          evidence: [fileEvidence(file, line, body.split("\n")[0]?.trim() || "")],
          remediation:
            "Move the gate first: read only the field the authorisation decision needs (e.g. `resource`), " +
            "run the check, then do the full validation.",
        });
        break;
      }
    }
    return findings;
  },
};
