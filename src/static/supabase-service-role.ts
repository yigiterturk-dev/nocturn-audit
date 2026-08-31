import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A01 — use of the Supabase service_role key (RLS bypass risk).
 * The service_role key bypasses RLS entirely; leaked to the client or used on
 * the wrong route, it opens access to all data.
 */

const SERVICE_ROLE =
  /(SERVICE_ROLE|service_role|SUPABASE_SERVICE_KEY|supabaseServiceRole|serviceRoleKey)/;

const isClientBundle = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return /\.(tsx|jsx)$/.test(f) || /(^|\/)components\//.test(f);
};

/**
 * Can this file NEVER LEAVE THE SERVER?
 *
 * The service_role key appearing in a maintenance script, a SQL migration or a
 * worker is BY DESIGN — bypassing RLS is the point there. In one run this rule
 * produced 36 "medium" findings across 4 projects: 17 of them in `scripts/*.mjs`
 * in one project, 3 of them in `.sql` files in another. None of them leaked to a
 * client (checked: no VITE_ or NEXT_PUBLIC_ prefix, no "use client" file).
 *
 * Calling those "medium findings" inflates the score and buries the real one.
 * Keep them as information — knowing where RLS is bypassed is valuable — but do
 * not count them as risk.
 */
const sunucuyaKilitli = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    // The ROOT directory requirement: a path like `lib/supabase/admin.ts` also
    // contains "supabase/", but it is a helper called from inside the app, not a
    // script. Without the anchor those two were confused.
    /^(scripts?|tools?|bin|migrations?|seeds?|supabase|worker|workers|db)\//.test(f) ||
    /\.(sql|mjs|cjs)$/.test(f) ||
    /(^|\/)server\.[cm]?[jt]s$/.test(f) ||
    /(^|\/)app\/api\/.*\/route\.[jt]s$/.test(f) ||
    /\.(config|test|spec)\.[cm]?[jt]s$/.test(f)
  );
};

export const supabaseServiceRole: StaticRule = {
  id: "a01-supabase-service-role-key",
  title: "Supabase service_role key in use (bypasses RLS)",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    // DOCUMENTATION IS NOT CODE.
    //
    // Once `.md` started being scanned, every sentence about "service_role" in
    // the docs became a finding — lines like "Supabase ships with the anon,
    // authenticated and service_role roles". There is no key there, just the
    // ROLE'S NAME. A security tool reporting its own security note as a hole is
    // the most irritating form of noise.
    const matches = ctx.grep(SERVICE_ROLE, (f) =>
      !/\.env/.test(f) && !/\.(md|mdx|txt|rst)$/i.test(f));
    const seen = new Set<string>();
    for (const m of matches) {
      const key = `${m.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const content = ctx.read(m.file) ?? "";
      const clientSide =
        /["']use client["']/.test(content) || isClientBundle(m.file);
      // In places the client can NEVER REACH (script/SQL/worker/api route) the
      // usage is the intended design → information, not a finding.
      const sunucuSabit = !clientSide && sunucuyaKilitli(m.file);
      findings.push({
        ruleId: this.id,
        owasp: this.owasp,
        // service_role in a client bundle → certain/critical. Server-side usage is
        // usually by design → heuristic (likely) at medium severity.
        severity: clientSide ? "critical" : sunucuSabit ? "info" : "medium",
        confidence: clientSide ? "certain" : sunucuSabit ? "certain" : "likely",
        title: sunucuSabit
          ? "service_role usage (server-locked — informational)"
          : this.title,
        description: clientSide
          ? "The service_role key appears in a client-side file (use client / .tsx). This key bypasses RLS entirely; leaked to the browser it grants full access to all data."
          : sunucuSabit
            ? "The service_role key is used in a file the client can never reach (a maintenance script, SQL, worker or API route) — this is by design, and bypassing RLS is the intended behaviour. Recorded as inventory rather than a finding, so you know where RLS is switched off."
            : "The service_role key is used in server code. Because it bypasses RLS, restrict it to endpoints that genuinely need it and enforce authorisation there, and make sure it never drifts into client code.",
        evidence: [fileEvidence(m.file, m.line, m.text)],
        remediation:
          "Never ship the service_role key in a client bundle. Use it server-side only, on as few endpoints as possible, with explicit authorisation checks — and prefer the anon key with RLS where you can.",
      });
    }
    return findings;
  },
};
