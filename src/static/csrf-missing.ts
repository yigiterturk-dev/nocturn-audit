import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";
import { bodyShape, findHandlers, isRouteFile } from "../core/route.js";

/**
 * A01 — no CSRF protection on state-changing routes.
 *
 * Flags POST/PUT/PATCH/DELETE handlers that authenticate via cookies or sessions
 * and show no CSRF token validation. (Bearer/Authorization-header APIs and
 * signed webhooks are excluded, since they are not exposed to CSRF.)
 */

const MUTATING_HANDLER =
  /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|(?:^|\s)(POST|PUT|PATCH|DELETE)\s*:\s*(?:async\s*)?\(|req\.method\s*===?\s*["'`](POST|PUT|PATCH|DELETE)["'`]/;

// Cookie/session-based identity (this is where CSRF risk lives).
const COOKIE_SESSION =
  /\bcookies\(\)|req\.cookies|request\.cookies|getServerSession|next-auth|getToken\s*\(|iron-session|express-session|\bsession\.user\b/i;

// Token/Bearer based → not exposed to CSRF.
const TOKEN_AUTH =
  /Authorization["'`\s:]|Bearer\s|x-api-key|apiKey\s*header|headers\.get\(\s*["'`]authorization/i;

// Signals of CSRF protection.
const CSRF_GUARD =
  /csrf|xsrf|x-csrf-token|verifyCsrf|csrfToken|__Host-|double[_-]?submit|origin\s*check|verifyOrigin|assertOrigin/i;

// A signed webhook → excluded.
const WEBHOOK =
  /webhook|constructEvent|stripe-signature|svix|x-hub-signature|verifySignature/i;

const isApiRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /\/route\.(ts|js)$/.test(f) ||
    /\/api\//.test(f) ||
    /pages\/api\//.test(f) ||
    /actions?\.(ts|js)$/.test(f)
  );
};

export const csrfMissing: StaticRule = {
  id: "a01-csrf-missing",
  title: "State-changing route has no CSRF protection",
  owasp: "A01:2021-Broken Access Control",
  severity: "medium",
  cwe: "CWE-352",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (!isApiRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      if (WEBHOOK.test(content)) continue;
      if (!MUTATING_HANDLER.test(content)) continue;
      if (!COOKIE_SESSION.test(content)) continue; // cookie/session based only
      if (TOKEN_AUTH.test(content)) continue; // Bearer/token → closed to CSRF
      if (CSRF_GUARD.test(content)) continue; // koruma var

      // DEFENCE IN DEPTH. A missing CSRF token does not by itself mean the route
      // is exploitable. Two common layers already close the door:
      //
      // 1) A JSON BODY: if the handler expects `request.json()`, a cross-site
      //    <form> cannot trigger it — a form can only send urlencoded or
      //    multipart; `application/json` requires a CORS preflight, and the
      //    preflight carries no cookie.
      // 2) A SameSite=Lax COOKIE: next-auth v4, Supabase SSR and iron-session
      //    default to Lax — on a cross-site POST the cookie is not sent AT ALL.
      //
      // One project's 10 findings were exactly this: next-auth v4 (Lax) plus
      // `request.json()`. A real gap (no explicit token), but the sentence "an
      // attacker can trigger requests with the victim's session" was not true.
      // THE BODY FORMAT COMES FROM THE TREE. Text search could not tell
      // `Response.json(...)` from `req.json()`: every handler writing a response
      // looked like it "expects a JSON body" and counted as protected. On the
      // tree only a read from the REQUEST object counts.
      const tree = ctx.ast(file);
      let jsonBody = /\b(request|req)\.json\s*\(/.test(content);
      if (tree) {
        const writers = findHandlers(tree).filter((h) => h.writer);
        // With no state-changing handler in the route file there is no CSRF surface.
        if (isRouteFile(file) && writers.length === 0) continue;
        if (writers.length) {
          // A CROSS-SITE HTML FORM CAN ONLY SEND GET/POST.
          // PUT/PATCH/DELETE'i tetiklemek fetch/XHR requires; o da CORS
          // preflight, and the preflight carries no cookie. So the real CSRF
          // surface is a POST handler that reads a FORM body.
          //
          // The first version asked "do all writing handlers read JSON"; a DELETE
          // that reads no body failed that test and unfairly pushed the file to
          // medium (two files in one project).
          const formluPost = writers.some(
            (h) => h.metod === "POST" && bodyShape(h.body) === "form",
          );
          jsonBody = !formluPost;
        }
      }
      // DO NOT ASSUME SameSite, READ IT.
      //
      // At first this looked at the library name only — "if it uses next-auth it
      // is Lax". Projects that write their own session failed that test and got
      // an unfair medium, even though they set their cookie with
      // `sameSite: "lax"`. A library name is an assumption; a cookie setting is
      // a measurement.
      const projedeLaxCerez = ctx
        .grep(/sameSite\s*:\s*["'`](lax|strict)["'`]/i)
        .length > 0;
      const laxVarsayilan =
        projedeLaxCerez ||
        /next-auth|getServerSession|iron-session|@supabase\/ssr|createServerClient/i.test(content);
      const katmanliSavunma = jsonBody && laxVarsayilan;

      // find the handler line
      const lines = content.split(/\r?\n/);
      let line = 1;
      let snippet = "";
      for (let i = 0; i < lines.length; i++) {
        if (MUTATING_HANDLER.test(lines[i])) {
          line = i + 1;
          snippet = lines[i];
          break;
        }
      }

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: katmanliSavunma ? "low" : "medium",
        description: katmanliSavunma
          ? "This state-changing handler has no explicit CSRF token check. It does expect a JSON body, and the session library uses the SameSite=Lax cookie default: a cross-site form cannot construct this request, and a preflighted JSON request carries no cookie. So it is NOT exploitable today — but the protection rests on a cookie default rather than an explicit check. Loosening SameSite, or accepting form bodies, opens it."
          : "A state-changing handler (POST/PUT/PATCH/DELETE) that authenticates via cookies appears to perform no CSRF token validation. An attacker can trigger forged requests using the victim's session cookie.",
        cwe: this.cwe,
        evidence: [fileEvidence(file, line, snippet || "mutating handler")],
        remediation:
          "Add CSRF token validation (double-submit cookie or a server-generated token). Use SameSite=Lax/Strict cookies and validate the Origin/Referer header. Where possible use an Authorization: Bearer token instead of a cookie.",
        remediationCode:
          "const origin = req.headers.get('origin');\n" +
          "if (origin && new URL(origin).host !== req.headers.get('host')) {\n" +
          "  return new Response('CSRF', { status: 403 });\n" +
          "}",
      });
    }
    return findings;
  },
};
