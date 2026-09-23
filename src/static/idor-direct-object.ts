import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A01 — IDOR paterni.
 * An id taken from a request parameter is used directly in a query, with no
 * ownership check (a user_id/owner match) anywhere nearby.
 */

// REAL object-ID sources. Behavioural query params such as 'format' are not IDOR
// → match only id/slug/uuid/*Id style keys.
const ID_SOURCE =
  /(params\.(id|slug|uuid|userId|\w*Id)\b|searchParams\.get\(\s*['"`](id|slug|uuid|\w*[iI]d|leadId|conversation_id)['"`]\s*\)|req\.query\.(id|\w*[iI]d)\b|query\.\w*[iI]d\b)/;

// a direct single-record query with that id
const QUERY_USE =
  /\.(eq|findUnique|findFirst|findById|where)\s*\(|WHERE\s+id\s*=/i;

const OWNERSHIP_HINTS =
  /(user_id|userId|owner|ownerId|auth\.uid\(\)|session\.user|currentUser|\.eq\(\s*['"]user)/i;

// If the route or handler's ownership boundary is protected by a guard
// (requireAdmin/requireGate/requireAuth) and the app is single-tenant, IDOR is
// n/a → drop the file. Real case: a route was reported as IDOR while four lines
// above it there were `getUser()` (401 otherwise) and `getUserRoleData()` →
// `permissions.includes("orders")` (403 otherwise). The rule only knew the
// requireX/getServerSession shapes and did not see the permission-list gate. In a
// single-tenant shop, staff with the "orders" permission can see every customer —
// the gate is there and it works.
const GUARD_HINTS =
  /(requireAdmin|requireGate|requireAuth|requireUser|requireSession|requirePermission|ensureAuth|assertAdmin|getServerSession|getUserRoleData|hasPermission|checkPermission|permissions\s*\.\s*includes\s*\(|\bgetUser\s*\(\s*\)|isAdmin\b|\bauth\(\)\s*;?)/i;

export const idorDirectObject: StaticRule = {
  id: "a01-idor-direct-object-reference",
  title: "Possible IDOR: direct object access with no ownership check",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      const f = file.replace(/\\/g, "/");
      if (!/(app\/|pages\/api\/|route\.|\/api\/|actions?\.|lib\/)/.test(f))
        continue;
      const content = ctx.read(file);
      if (!content) continue;
      // If the file has a guard (requireAdmin/requireGate/requireAuth) the ownership
      // boundary is already protected; in a single-tenant/single-admin app IDOR is n/a → drop.
      if (GUARD_HINTS.test(content)) continue;
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        if (!ID_SOURCE.test(lines[i])) continue;
        // look for a direct query use on the same or the next ~8 lines
        const window = lines.slice(i, i + 9).join("\n");
        if (!QUERY_USE.test(window)) continue;
        // is there an ownership check (wide window)
        const contextWindow = lines
          .slice(Math.max(0, i - 6), i + 12)
          .join("\n");
        if (OWNERSHIP_HINTS.test(contextWindow)) continue;

        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "high",
          description:
            "An id taken from the request is used directly in a single-record query with no nearby ownership filter (user_id/owner). It may allow access to another user's record (IDOR).",
          evidence: [fileEvidence(file, i + 1, lines[i])],
          remediation:
            "Add the session user id to the query (e.g. .eq('user_id', session.user.id)), or enforce row-level access with RLS.",
        });
        break; // one finding per file is enough
      }
    }
    return findings;
  },
};
