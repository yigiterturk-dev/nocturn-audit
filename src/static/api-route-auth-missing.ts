import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { callsAuthHelper, collectAuthHelpers } from "../core/auth-helpers.js";

/**
 * A01 — no auth check in an API route.
 * Flags handlers under app/api/**\/route.ts and pages/api/** that read or write
 * data without any recognisable auth check.
 */

const AUTH_HINTS = [
  /\bauth\s*\(/i,
  /getServerSession/,
  /currentUser\s*\(/,
  /auth\(\)/,
  /getUser\s*\(/,
  /getSession/,
  /clerkClient/,
  /requireUser/,
  /verify(Jwt|Token|Auth|Session)/i,
  /\bsession\b/,
  /supabase[\s\S]{0,40}\.auth\./,
  /x-api-key/i,
  /unstable_getServerSession/,
  /withApiAuth/,
  // ek auth/yetki sinyalleri (FP azaltma)
  /getToken\s*\(/,
  /\bjwt\.verify\s*\(/,
  /\bbearer\b/i,
  /authorization/i,
  /CRON_SECRET/,
  /process\.env\.\w*(SECRET|TOKEN|API_KEY)\b[\s\S]{0,80}(===|==|!==|!=|includes|timingSafeEqual)/i,
  /isAdmin|isAuthenticated|isAuthorized|authorize\b|requireAuth|requireAdmin|requireUser|requireOwner|requireRole|requireMember|isOwner|ensureOwner|requireGate|ensureAuth|checkAuth|guard|yoneticiMi/i,
];

// Signals that the handler touches the database — without them the route is
// most likely public (og image, health, redirect, proxy) and we do not report.
const DB_ACCESS =
  /(prisma\.|\bdb\.|drizzle|mongoose|sequelize|\bknex\b|supabase[\s\S]{0,40}\.from\(|\.from\(["'`]?\w|\.query\s*\(|sql`|\.findMany\(|\.findUnique\(|\.findFirst\(|\.insert\(|\.update\(|\.delete\(|\.create\(|\.upsert\(|\.collection\()/i;

// Next routes ONLY the root `app/` (or `src/app/`) directory. A nested `app/`
// folder such as `examples/d1/app/api/...` is NEVER SERVED, and calling code
// that cannot run "missing auth" is noise. In one run this was a project's only
// high finding: the notes route of a Cloudflare D1 sample app kept as an example.
const ROOT_ROUTE = /^(?:src\/)?(?:app|pages)\//;

const isApiRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  if (!ROOT_ROUTE.test(f)) return false;
  return (
    /(^|\/)app\/.*\/route\.(ts|js|tsx|jsx)$/.test(f) ||
    /(^|\/)pages\/api\/.*\.(ts|js|tsx|jsx)$/.test(f)
  );
};

// Derive the API path from the route file: app/api/clients/[id]/route.ts →
// /api/clients (dynamic [id] segments are dropped).
const apiPathOf = (file: string): string => {
  const m = file.replace(/\\/g, "/").match(/app\/(api\/.*?)\/route\.\w+$/);
  if (!m) return "";
  return "/" + m[1].replace(/\/\[[^\]]+\]/g, "");
};

// Is the route protected at the Next.js middleware/proxy LAYER? (In Next 16
// middleware.ts became proxy.ts.) Many projects do auth in a single middleware
// rather than in the handler; a rule that looks at handlers reads that as
// "unauthenticated" (an FP). Real case: a proxy.ts protected /api/clients with
// an auth cookie and a 403, while the handler itself carried no auth code.
const isProtectedByMiddleware = (
  read: (p: string) => string | null,
  file: string,
): boolean => {
  const mw =
    read("proxy.ts") ?? read("src/proxy.ts") ??
    read("middleware.ts") ?? read("src/middleware.ts") ??
    read("proxy.js") ?? read("middleware.js");
  if (!mw) return false;
  // Does the middleware actually perform auth?
  const hasAuth =
    /(AUTH_COOKIE|readSession|getSession|getToken|verifyToken|session|cookies\.get|\b401\b|\b403\b|redirect\s*\()/i.test(mw);
  if (!hasAuth) return false;
  const path = apiPathOf(file);
  if (!path) return false;
  // If this path is marked PUBLIC in the middleware, the middleware does NOT
  // protect it and the rule may correctly flag it.
  const publicMatch = mw
    .split(/\r?\n/)
    .some((l) => /public|acik|açık|herkese|whitelist/i.test(l) && l.includes(path));
  if (publicMatch) return false;
  // The path is explicitly on the protected list, OR the middleware protects
  // /api wholesale (matcher / startsWith('/api')). Either way → protected.
  const referenced = mw.includes(path);
  const broadApi = /matcher[\s\S]{0,300}?\/api|startsWith\(\s*["'`]\/api/i.test(mw);
  return referenced || broadApi;
};

// Routes that PRODUCE auth rather than consume it — login/register/callback and
// friends must be public by design; looking for auth here is wrong.
const isAuthBoundaryRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/").toLowerCase();
  return /\/(login|log-in|signin|sign-in|register|signup|sign-up|logout|sign-out|forgot-password|reset-password|verify-email|magic-link|callback|oauth|auth)\b/.test(
    f,
  );
};

// Is this a public form endpoint? It has rate limiting and input validation AND
// only inserts or notifies (never reads a user-owned resource) → a lead,
const looksLikePublicForm = (content: string): boolean => {
  const hasRateLimit =
    /rateLimit|rate_limit|enforceWriteLimit|ratelimit|Ratelimit|limiter\.|@upstash\/ratelimit|checkRateLimit/i.test(
      content,
    );
  // Zod/yup/joi SCHEMA validation, or hand-written validation / double opt-in signals.
  const hasValidation =
    /\.safeParse\(|z\.object\(|zodResolver|yup\.|joi\.|\.parse\(|EMAIL_RE|signOptIn|opt-?in|double[_-]?opt|confirmation|sanitize|\bvalidate\b|RE\.test\(/i.test(
      content,
    );
  // Only insert/upsert/create (never reads a user-owned resource).
  const insertOnly = /\.(create|upsert|insert|createMany)\s*\(/i.test(content);
  // With no READ of a user-owned resource (no ownership surface) it counts as safely public.
  const readsUserData =
    /\.(findUnique|findFirst|findMany)\s*\(|\.select\s*\([\s\S]{0,60}(user_id|owner)/i.test(
      content,
    );
  return hasRateLimit && hasValidation && insertOnly && !readsUserData;
};

// Routes that are public by convention — auth is not expected, do not report.
const isPublicByConvention = (file: string, content: string): boolean => {
  const f = file.replace(/\\/g, "/").toLowerCase();
  // Auth boundary (login/register/callback) → must be public.
  if (isAuthBoundaryRoute(file)) return true;
  // A public form with rate limiting and validation (lead, newsletter, contact).
  if (looksLikePublicForm(content)) return true;
  // Health/status, sitemap/robots/manifest, og and image endpoints.
  if (/\/(health|healthz|status|ping|readyz|livez)\//.test(f)) return true;
  if (/\/(sitemap|robots|manifest)\b/.test(f)) return true;
  // Public by design: /public/ (a shared resource reached with a token),
  // /unsubscribe (CAN-SPAM one-click), /track/ and /pixel/ (email open and click
  // tracking — loaded by the recipient's client, no session). Looking for a
  // session here is wrong; access is granted by a URL token or slug.
  if (/\/(public|unsubscribe|track|pixel|beacon|open)\//.test(f)) return true;
  if (/\/(og|opengraph-image|twitter-image|icon|apple-icon|favicon)\b/.test(f))
    return true;
  if (/ImageResponse|new\s+ImageResponse/.test(content)) return true;
  // NextAuth / Clerk / auth-provider catch-all handlers.
  if (/\[\.\.\.(nextauth|clerk|auth|kinde|betterauth)\]/.test(f)) return true;
  if (/\bNextAuth\s*\(|toNextJsHandler|createRouteHandler|handlers\s*\}/.test(content))
    return true;
  // Webhook endpoints with signature verification — out of scope here (webhook-signature is a separate rule).
  if (
    /webhook|\/callback\//.test(f) &&
    /(constructEvent|svix|Webhook\(|wh\.verify|x-hub-signature|stripe-signature|timingSafeEqual|createHmac|verifySignature|verifyWebhook)/i.test(
      content,
    )
  )
    return true;
  return false;
};

const HANDLER_RE =
  /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=/;
const MUTATION_RE =
  /export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=/;

export const apiRouteAuthMissing: StaticRule = {
  id: "a01-api-route-auth-missing",
  title: "API route has no authentication check",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  // Heuristic: many routes are public by design (webhook/health/public GET).
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    // The project's OWN auth helpers. A fixed list did not recognise names like
    // `getPanelActor` and marked protected routes as "unauthenticated".
    const authHelpers = collectAuthHelpers(ctx);
    for (const file of ctx.files) {
      if (!isApiRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      if (!HANDLER_RE.test(content)) continue;
      if (AUTH_HINTS.some((re) => re.test(content))) continue;
      if (callsAuthHelper(content, authHelpers)) continue;
      if (isPublicByConvention(file, content)) continue;
      if (isProtectedByMiddleware(ctx.read, file)) continue;
      // Routes that never touch the database are usually public or helpers — high FP; skip.
      if (!DB_ACCESS.test(content)) continue;

      const isMutation = MUTATION_RE.test(content);

      // A CACHED RESPONSE CANNOT BE USER-SPECIFIC.
      //
      // `export const revalidate = 3600` ya da `dynamic = "force-static"`
      // present, Next PRODUCES this response once and serves it identically to
      // everyone. Saying "no auth" about such an endpoint is wrong: content that
      // varies per identity cannot exist there — it is a design choice, not an
      // access-control defect. One project's three "open" endpoints were exactly
      // this, and all of them had been labelled false positives.
      const onbellekliPublic =
        !isMutation &&
        /export\s+const\s+(revalidate\s*=|dynamic\s*=\s*["'`](force-static|error))/.test(
          content,
        );
      if (onbellekliPublic) continue;

      // Is there NO session or cookie signal in the file at all? (If there is,
      // auth was attempted but not recognised — then the suspicion is real.)
      const noSessionSignal =
        !isMutation && !/session|cookies\(\)|getUser|getToken|auth\(|Authorization/i.test(content);

      // find the handler line to use as evidence
      const lines = content.split(/\r?\n/);
      let line = 1;
      let snippet = lines[0] ?? "";
      for (let i = 0; i < lines.length; i++) {
        if (HANDLER_RE.test(lines[i])) {
          line = i + 1;
          snippet = lines[i];
          break;
        }
      }
      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        // Only unprotected handlers that WRITE to the database are high; read-only
        // ones (which may be public) are low — we do not escalate without solid
        // IDOR or leak evidence. Read-only plus no session signal at all most
        // likely means a DELIBERATELY open endpoint. Calling that a "finding" sends
        // the team chasing nothing; listing it as inventory is right: "this is read
        // without identity — on purpose?"
        severity: isMutation ? "high" : noSessionSignal ? "info" : "low",
        confidence: "likely",
        description: isMutation
          ? "This API route defines a mutating handler (POST/PUT/PATCH/DELETE) that writes to the database, with no recognisable auth or session check inside it. It may allow unauthorised data changes."
          : "This API route defines a handler that reads the database, with no recognisable auth or session check inside it. Unless the data is public it may allow unauthorised reads (ignore it if the endpoint serves public data).",
        evidence: [fileEvidence(file, line, snippet)],
        remediation:
          "Verify the session or user at the top of the handler (Clerk auth(), Supabase getUser(), getServerSession) and return 401/403 when unauthorised. If the endpoint really is public, document it explicitly.",
      });
    }
    return findings;
  },
};
