import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A01 (live) — sensitive endpoints reachable without auth (such as /admin).
 * Non-destructive: GET only, with no credentials. Looks for 200 plus a not-auth signal.
 */

const PATHS = ["/admin", "/dashboard/admin", "/api/admin", "/api/users"];

// is the response real content rather than a login page or redirect
const looksProtected = (status: number, body: string, headers: Record<string, string>): boolean => {
  if ([301, 302, 303, 307, 308].includes(status)) {
    const loc = (headers["location"] ?? "").toLowerCase();
    if (/login|signin|sign-in|auth|clerk|accounts\./.test(loc)) return true;
  }
  if ([401, 403].includes(status)) return true;
  if (status === 404) return true;
  if (/(sign in|log in|giriş yap|unauthorized|yetkisiz|please authenticate)/i.test(body))
    return true;
  return false;
};

export const liveOpenEndpoints: LiveRule = {
  id: "a01-live-open-admin-endpoints",
  title: "Live: sensitive endpoint reachable without authentication",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    // THE CATCH-ALL CHECK.
    //
    // SPAs and Next.js apps return 200 and the same HTML shell for EVERY unknown
    // path. In that case "/admin returned 200" says nothing — a path that does not
    // exist returns 200 too. Without this distinction the rule produces four false
    // HIGH findings for every SPA.
    //
    // We probe a random, definitely non-existent path; if that also returns 200 the
    // server answers 200 to everything and this rule cannot measure this target.
    const olmayan = await ctx.probe(`/nocturn-audit-yok-${Date.now().toString(36)}`);
    if (olmayan.ok && olmayan.status === 200) {
      return [{
        ruleId: this.id,
        title: "Open-endpoint scan not possible: the server returns 200 for every path",
        owasp: this.owasp,
        severity: "info",
        confidence: "certain",
        description:
          "A path that does not exist also returned 200, so this server catches unknown paths as well " +
          "(an SPA or Next.js shell). Detecting open endpoints by status code is meaningless on this target — " +
          "reporting 'no findings' would really mean 'could not measure'.",
        evidence: [httpEvidence(olmayan.requestLine, olmayan.responseLine)],
        remediation:
          "Verify these endpoints by hand: does an unauthenticated request return actual DATA, or just the app " +
          "shell? For API endpoints, returning 401/403 beats returning an HTML shell.",
      }];
    }

    const findings: Finding[] = [];
    for (const path of PATHS) {
      const res = await ctx.probe(path);
      if (!res.ok) continue;
      if (res.status !== 200) continue;
      if (looksProtected(res.status, res.bodySnippet, res.headers)) continue;

      findings.push({
        ruleId: this.id,
        title: `Reachable without authentication: ${path}`,
        owasp: this.owasp,
        severity: "high",
        description: `${path} returned 200 without any credentials and the body does not look like a login page or redirect. Authorisation may be missing. (Manual verification recommended.)`,
        evidence: [
          httpEvidence(
            res.requestLine,
            `HTTP ${res.status} ${res.statusText}\n${res.bodySnippet.slice(0, 160)}`,
          ),
        ],
        remediation:
          "Protect this endpoint with auth at the middleware or route level; return 401/403 for unauthorised requests, or redirect to login.",
      });
    }
    return findings;
  },
};
