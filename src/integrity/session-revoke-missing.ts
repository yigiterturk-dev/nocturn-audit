import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A07 — access was revoked but the open session was not closed.
 *
 * Shutting a door does not remove whoever already walked through it. Changing a
 * password, revoking access and closing a setup path are all easy to declare
 * done while half finished. Whoever holds the cookie stays inside.
 */
const ERISIM_KESME = /\b(changePassword|resetPassword|disable\w*|revokeAccess|deactivate\w*|suspend\w*|lockAccount)\s*\(/;
const OTURUM_IPTAL = /\b(revoke\w*Session|destroySession|invalidateSession|killSession|signOutAll|deleteSessions|clearSessions)/i;

export const sessionRevokeMissing: StaticRule = {
  id: "int-session-revoke-missing",
  title: "Access is revoked but open sessions stay alive",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.(ts|js|mjs)$/.test(file) || /\.(test|spec)\./.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      // Files with no notion of a session are not our concern.
      if (!/session|oturum/i.test(content)) continue;

      for (const body of content.split(/export (?:async )?function /).slice(1)) {
        const ad = body.slice(0, body.indexOf("(")).trim();
        if (!ERISIM_KESME.test(`${ad}(`)) continue;
        // Roughly bound the function body.
        const kesit = body.slice(0, 2500);
        if (OTURUM_IPTAL.test(kesit)) continue;

        const line = content.slice(0, content.indexOf(body)).split("\n").length;
        findings.push({
          ruleId: "int-session-revoke-missing",
          title: "Access is revoked but open sessions stay alive",
          owasp: "A07:2021-Identification & Authentication Failures",
          severity: "high",
          confidence: "likely",
          description:
            `\`${ad}\` in \`${file}\` revokes access but never invalidates a session. ` +
            "Whoever still holds the old cookie stays inside afterwards.",
          evidence: [fileEvidence(file, line, `${ad}(...)`)],
          remediation:
            "Every path that revokes access should also close that person's open sessions. On a password " +
            "change, keep the acting user's OWN session — this is a fix, not a punishment.",
        });
      }
    }
    return findings;
  },
};
