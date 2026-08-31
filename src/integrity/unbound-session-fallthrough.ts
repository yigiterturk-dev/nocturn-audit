import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";
import { collectAuthHelpers } from "../core/auth-helpers.js";

/**
 * A07 — an UNBOUND session is not rejected; it falls through to a default identity.
 *
 * Identity resolution gets written like this: "if the session is bound to an
 * account, use that account's identity" — and then, without saying what happens
 * when it is NOT bound, the function carries on and produces an identity anyway.
 * That identity is usually read from the environment, and it is elevated.
 *
 * A missing binding is not exotic, it is ordinary: a stale cookie, a
 * half-finished migration, a deleted membership, or a session opened through a
 * setup path that has since been closed. All of them land here.
 *
 * Real case: five sessions opened with a shared password were still alive after
 * personal accounts had been created. The gate rejected NEW logins, but because
 * those sessions had an empty `subjectKind` they could not enter the bound-account
 * branch and fell through to the default identity below — as admin. Shutting a
 * door does not remove whoever already walked through it.
 *
 * The right shape: an unbound session must be rejected EXPLICITLY, and the
 * decision belongs at the single point every request passes through.
 */

/** A binding check shaped like `if (session?.kind && ...)`. */
const BAG_KONTROLU =
  /if\s*\(\s*(\w+)\?\.\s*(\w*(?:kind|type|subject|binding|role|account)\w*)\b/i;

/** An expression that explicitly rejects an unbound session. */
const EXPLICIT_REJECT =
  /!\s*\w+\?*\.\s*\w*(kind|type|subject|binding)\w*[\s\S]{0,80}?return\s+(null|undefined)|return\s+(null|undefined)[\s\S]{0,40}?\/\/\s*(unbound|bağsız)/i;

export const unboundSessionFallthrough: StaticRule = {
  id: "int-unbound-session-fallthrough",
  title: "An unbound session is not rejected; it falls through to a default identity",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  cwe: "CWE-1188",
  run(ctx: StaticContext): Finding[] {
    const yardimcilar = collectAuthHelpers(ctx);
    if (!yardimcilar.size) return [];

    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.(ts|js|mjs|cjs)$/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      for (const ad of yardimcilar) {
        const bas = content.search(new RegExp(`(export\\s+)?(async\\s+)?function\\s+${ad}\\b`));
        if (bas < 0) continue;
        const body = content.slice(bas, bas + 2500);

        const bag = body.match(BAG_KONTROLU);
        if (!bag) continue;

        // Is an identity still produced AFTER the binding check?
        const sonrasi = body.slice(body.indexOf(bag[0]) + bag[0].length);
        const kimlikUretiyor =
          /return\s*\{[\s\S]{0,300}?\b(role|email|id)\b/.test(sonrasi)
          || /process\.env\.\w+[\s\S]{0,200}?\b(role|actor|email)\b/i.test(sonrasi);
        if (!kimlikUretiyor) continue;

        // No problem when the unbound session is explicitly rejected.
        if (EXPLICIT_REJECT.test(body)) continue;

        // FAIL-CLOSED DEFAULT: if the function falls back to a least-privilege role
        // (viewer/guest/anonymous/none…), this is not an identity LEAK but a safe
        // default — an unbound session gains no elevated privilege.
        // The real risk is a default of admin/owner/a real user.
        // (Delta resolveRole istemci hook'u: default 'viewer'.)
        if (/return\s+['"`](viewer|guest|anonymous|anon|public|none|unauthenticated|read[-_]?only|nobody)['"`]/i.test(body))
          continue;

        const lineNo = content.slice(0, bas + body.indexOf(bag[0])).split("\n").length;
        findings.push({
          ruleId: "int-unbound-session-fallthrough",
          title: "An unbound session is not rejected; it falls through to a default identity",
          owasp: "A07:2021-Identification & Authentication Failures",
          severity: "high",
          confidence: "likely",
          cwe: "CWE-1188",
          description:
            `\`${ad}\` in \`${file}\` resolves the bound account from the session's \`${bag[2]}\` field; ` +
            "but when the binding is ABSENT the function carries on and still produces an identity. " +
            "A missing binding is not exotic: a stale cookie, a half-finished migration, or a session " +
            "opened through a since-closed setup path all land here.",
          evidence: [fileEvidence(file, lineNo, bag[0].trim())],
          remediation:
            `Reject the unbound session EXPLICITLY: \`if (session && !session.${bag[2]}) return null;\`. ` +
            "Put that decision at the single point every request passes through. And when a setup path is " +
            "closed, invalidate the sessions it opened — shutting a door does not remove whoever already " +
            "walked through it.",
        });
        break;
      }
    }
    return findings;
  },
};
