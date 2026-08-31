import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext } from "../core/rule.js";
import type { StandardsCheck } from "./types.js";
import { apiRouteAuthMissing } from "../static/api-route-auth-missing.js";
import { hardcodedSecrets } from "../static/hardcoded-secrets.js";

/**
 * Standards profile — SECURITY checks.
 * Source: the security standard — rate limiting, auth guards, env protection,
 * security headers, RLS, input validation.
 */

// ---- shared helpers ---------------------------------------------------------

const norm = (f: string): string => f.replace(/\\/g, "/");

const isApiRoute = (file: string): boolean => {
  const f = norm(file);
  return (
    /(^|\/)app\/.*\/route\.(ts|js|tsx|jsx)$/.test(f) ||
    /(^|\/)pages\/api\/.*\.(ts|js|tsx|jsx)$/.test(f)
  );
};

/** Keep lockfiles and generated json out of the grep (a source of FPs). */
const isSourceFile = (file: string): boolean => {
  const f = norm(file);
  return !/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|.*\.min\.(js|css))$/.test(f);
};

const hasApiRoutes = (ctx: StaticContext): boolean =>
  ctx.files.some(isApiRoute);

/** Is there server-side code — without it the rate-limit and auth checks are meaningless. */
const hasServerSide = (ctx: StaticContext): boolean =>
  hasApiRoutes(ctx) ||
  ctx.project.stack.framework === "node" ||
  ctx.grep(/\bexpress\s*\(\s*\)|createServer\s*\(|\bfastify\s*\(/, isSourceFile).length > 0;

// ---- 1. Rate limit ----------------------------------------------------------

const RATELIMIT_HINT =
  /(@upstash\/ratelimit|express-rate-limit|rate-?limit|rateLimit|Ratelimit|throttle|limiter\b|slowDown|bottleneck|tokenBucket|leakyBucket)/i;

export const stdRateLimit: StandardsCheck = {
  id: "std-sec-rate-limit",
  title: "Rate limiting in place",
  category: "security",
  level: "warning",
  description:
    "Standard: every project rate-limits its form and API endpoints (brute-force and abuse protection). Looks for a known rate-limit library or middleware in the code.",
  remediation:
    "Add IP + identity based rate limiting to API and form endpoints (@upstash/ratelimit for Next.js, express-rate-limit for Express). Cover login, contact and payment endpoints at minimum.",
  run(ctx) {
    if (!hasServerSide(ctx)) {
      return {
        status: "na",
        detail: "No API routes or server-side code found — rate limiting is meaningless at this layer.",
      };
    }
    const hits = ctx.grep(RATELIMIT_HINT, isSourceFile);
    if (hits.length > 0) {
      const h = hits[0];
      return {
        status: "pass",
        detail: `Rate limiting found (${hits.length} match(es)).`,
        evidence: [fileEvidence(h.file, h.line, h.text)],
      };
    }
    return {
      status: "open",
      detail:
        "No rate-limit library or middleware found anywhere. API endpoints may be open to brute force and spam.",
    };
  },
};

// ---- 2. Auth guard (unprotected API route) ----------------------------------

export const stdAuthGuard: StandardsCheck = {
  id: "std-sec-auth-guard",
  title: "API routes behind an auth guard",
  category: "security",
  level: "critical",
  description:
    "Standard: every endpoint that needs auth checks the session. Reuses the a01-api-route-auth-missing heuristic — routes that touch the database without any auth signal.",
  remediation:
    "Verify the session or user at the top of the handler (Clerk auth(), Supabase getUser(), getServerSession) and return 401/403 when unauthorised. Document endpoints that are genuinely public.",
  async run(ctx) {
    if (!hasApiRoutes(ctx)) {
      return {
        status: "na",
        detail: "Projede app/api ya da pages/api route'u yok.",
      };
    }
    const findings = (await Promise.resolve(
      apiRouteAuthMissing.run(ctx),
    )) as Finding[];
    if (findings.length === 0) {
      return {
        status: "pass",
        detail: "Every API route that touches the database carries an auth signal (or matches a known public pattern).",
      };
    }
    const mutations = findings.filter((f) => f.severity === "high");
    const evidence = findings.slice(0, 5).flatMap((f) => f.evidence);
    // Heuristic check: ask for manual confirmation instead of asserting a failure (false-positive guard).
    if (mutations.length > 0) {
      return {
        status: "manual",
        detail: `${mutations.length} route(s) that WRITE to the database carry no auth signal (${findings.length} suspicious routes in total). Unless these are deliberately public this is a serious hole — verify by hand.`,
        evidence,
      };
    }
    return {
      status: "manual",
      level: "warning",
      detail: `${findings.length} read-only route(s) carry no auth signal. Unless the data is public this may allow unauthorised reads — verify by hand.`,
      evidence,
    };
  },
};

// ---- 3. Env protection -------------------------------------------------------

export const stdEnvProtection: StandardsCheck = {
  id: "std-sec-env-protection",
  title: ".env protected (gitignored, never committed)",
  category: "security",
  level: "critical",
  description:
    "Standard: API keys live in .env, .env lives in .gitignore, and .env is never committed. Checks git tracking status and the .gitignore pattern.",
  remediation:
    "Add `.env*` (and `!.env.example`) to .gitignore. If a .env was committed, untrack it with `git rm --cached`, purge it from history and rotate EVERY secret it held.",
  run(ctx) {
    const gitignore = ctx.read(".gitignore") ?? "";
    const ignoresEnv = /(^|\n)\s*\.?\*?\.env(\b|\*|\.)/.test(gitignore);

    const envFiles = ctx.files.filter((f) => {
      const base = norm(f).split("/").pop() ?? "";
      return /^\.env/.test(base) && !/\.example|\.sample|\.template/.test(base);
    });

    const tracked = envFiles.filter((f) => {
      const content = ctx.read(f) ?? "";
      const hasRealValue = /^[A-Z0-9_]+\s*=\s*[^\s#][^\n]{6,}/m.test(content);
      return hasRealValue && ctx.isTracked(f);
    });

    if (tracked.length > 0) {
      return {
        status: "open",
        detail: `${tracked.length} .env file(s) with real values are tracked by git: ${tracked.map(norm).join(", ")}. This is an outright secret leak.`,
        evidence: tracked.map((f) => fileEvidence(f, 1, "(.env contents redacted)")),
      };
    }
    if (!ignoresEnv && ctx.exists("package.json")) {
      return {
        status: "open",
        level: "warning",
        detail: gitignore
          ? ".gitignore exists but has no .env pattern — a secret can be committed by accident."
          : "No .gitignore at all — .env files are unprotected.",
        evidence: [fileEvidence(".gitignore", 1, gitignore ? "(no .env pattern)" : "(file missing)")],
      };
    }
    if (!ctx.isGitRepo && envFiles.length > 0) {
      return {
        status: "manual",
        detail: "Not a git repository — the commit status of .env could not be verified. Check wherever the repository actually lives.",
      };
    }
    return {
      status: "pass",
      detail: ".gitignore covers .env and no .env file is tracked.",
    };
  },
};

// ---- 4. Hardcoded secret -----------------------------------------------------

export const stdHardcodedSecret: StandardsCheck = {
  id: "std-sec-hardcoded-secret",
  title: "No secrets hardcoded in source",
  category: "security",
  level: "critical",
  description:
    "Standard: API keys and secrets are never hardcoded. Backed by the a02-hardcoded-secret rule (provider patterns plus entropy).",
  remediation:
    "Move secrets into .env and read them via process.env; revoke and reissue any exposed key from the provider dashboard.",
  async run(ctx) {
    const findings = (await Promise.resolve(
      hardcodedSecrets.run(ctx),
    )) as Finding[];
    if (findings.length === 0) {
      return { status: "pass", detail: "No known provider pattern and no high-entropy embedded secret found." };
    }
    const certain = findings.filter((f) => f.confidence !== "likely");
    const evidence = findings.slice(0, 5).flatMap((f) => f.evidence);
    if (certain.length > 0) {
      return {
        status: "open",
        detail: `${certain.length} certain hardcoded secret(s) found (${findings.length} matches in total). Revoke these keys and move them into .env.`,
        evidence,
      };
    }
    return {
      status: "manual",
      detail: `${findings.length} possible hardcoded secret(s) (entropy heuristic) — check by hand whether these are real secrets or placeholders.`,
      evidence,
    };
  },
};

// ---- 5. Security headers -------------------------------------------------------

const NEXT_CONFIGS = ["next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs"];
const REQUIRED_HEADERS = [
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Strict-Transport-Security",
  "Referrer-Policy",
];

export const stdSecurityHeaders: StandardsCheck = {
  id: "std-sec-headers",
  title: "Security headers configured",
  category: "security",
  level: "warning",
  description:
    "Standard: the pre-deploy checklist includes security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy). Scans next.config and vercel.json.",
  remediation:
    "Declare CSP, X-Frame-Options: DENY/SAMEORIGIN, X-Content-Type-Options: nosniff, Strict-Transport-Security and Referrer-Policy in next.config headers() (or the vercel.json \"headers\" block).",
  run(ctx) {
    const sources: Array<{ file: string; content: string }> = [];
    for (const f of NEXT_CONFIGS) {
      const c = ctx.read(f);
      if (c != null) sources.push({ file: f, content: c });
    }
    const vercel = ctx.read("vercel.json");
    if (vercel != null) sources.push({ file: "vercel.json", content: vercel });
    // Headers can also be set in middleware. Next 16 moved middleware to proxy.ts,
    // and the CSP nonce is generated there. Without reading proxy.ts a nonce-based
    // CSP looks "missing" — the report of a lone missing CSP while the other
    // headers sat in next.config.ts came from exactly this blind spot.
    for (const f of [
      "middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js",
      "proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js",
    ]) {
      const c = ctx.read(f);
      if (c != null) sources.push({ file: f, content: c });
    }

    const isNext = ctx.project.stack.framework === "next";
    if (sources.length === 0) {
      if (!isNext) {
        return {
          status: "manual",
          level: "info",
          detail:
            "No next.config, vercel.json, middleware or proxy.ts found. Headers may be set at the hosting layer (Cloudflare, nginx) — verify by hand.",
        };
      }
      return {
        status: "open",
        detail: "A Next.js project with no file that could declare headers (next.config / vercel.json / middleware / proxy.ts).",
      };
    }

    const combined = sources.map((s) => s.content).join("\n");
    const missing = REQUIRED_HEADERS.filter(
      (h) => !new RegExp(h, "i").test(combined),
    );
    if (missing.length === 0) {
      return {
        status: "pass",
        detail: `Every expected security header is declared (${sources.map((s) => s.file).join(", ")}).`,
      };
    }
    if (missing.length === REQUIRED_HEADERS.length) {
      return {
        status: "open",
        detail: `No security header is declared at all (looked in: ${sources.map((s) => s.file).join(", ")}).`,
        evidence: [fileEvidence(sources[0].file, 1, "(no security header)")],
      };
    }
    return {
      status: "open",
      level: "info",
      detail: `Missing headers: ${missing.join(", ")} (looked in: ${sources.map((s) => s.file).join(", ")}).`,
      evidence: [fileEvidence(sources[0].file, 1, `eksik: ${missing.join(", ")}`)],
    };
  },
};

// ---- 6. Supabase RLS ----------------------------------------------------------

export const stdSupabaseRls: StandardsCheck = {
  id: "std-sec-rls",
  title: "Supabase RLS policies declared",
  category: "security",
  level: "warning",
  description:
    "Standard: a Supabase project isolates data with RLS. Looks for ENABLE ROW LEVEL SECURITY / CREATE POLICY in migration and SQL files (heuristic — policies may exist only in the dashboard).",
  remediation:
    "Declare `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;` plus matching `CREATE POLICY` for every table, and commit them as migrations instead of leaving them in the dashboard.",
  run(ctx) {
    if (ctx.project.stack.db !== "supabase") {
      return { status: "na", detail: "This project does not use Supabase." };
    }
    const hits = ctx.grep(
      /(ENABLE\s+ROW\s+LEVEL\s+SECURITY|CREATE\s+POLICY)/i,
      (f) => /\.(sql|md|mdx)$/i.test(f) && isSourceFile(f),
    );
    if (hits.length > 0) {
      const h = hits[0];
      return {
        status: "pass",
        detail: `RLS statements found (${hits.length} match(es)) — still confirm the policies cover EVERY table.`,
        evidence: [fileEvidence(h.file, h.line, h.text)],
      };
    }
    return {
      status: "manual",
      detail:
        "No RLS policy anywhere in the repository. Policies may exist in the Supabase dashboard — check it table by table; if they do not, every row is readable with the anon key.",
    };
  },
};

// ---- 7. Input validation --------------------------------------------------------

const VALIDATION_HINT =
  /(\bzod\b|z\.object\(|\.safeParse\(|zodResolver|\byup\b|yup\.|joi\.|\bjoi\b|valibot|class-validator|express-validator)/;

export const stdInputValidation: StandardsCheck = {
  id: "std-sec-input-validation",
  title: "Input validation in place",
  category: "security",
  level: "info",
  description:
    "Standard: validate input at every system boundary. Looks for a known schema validation library (zod/yup/joi/valibot) — it cannot prove the library is used on every endpoint.",
  remediation:
    "Validate with a schema library such as zod in API routes and form handlers (`schema.safeParse(body)`), and never pass an unvalidated body to the database.",
  run(ctx) {
    if (!hasServerSide(ctx)) {
      return { status: "na", detail: "No server-side code — input validation does not apply at this layer." };
    }
    const pkg = ctx.read("package.json") ?? "";
    const inDeps = /"(zod|yup|joi|valibot|class-validator|express-validator)"\s*:/.test(pkg);
    const hits = ctx.grep(VALIDATION_HINT, (f) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f) && isSourceFile(f));
    if (inDeps || hits.length > 0) {
      const ev = hits[0]
        ? [fileEvidence(hits[0].file, hits[0].line, hits[0].text)]
        : [fileEvidence("package.json", 1, "(validation library in dependencies)")];
      return {
        status: "pass",
        detail: `Schema validation found${hits.length ? ` (${hits.length} match(es))` : " (package.json)"} — confirm by code review that it is applied on every endpoint.`,
        evidence: ev,
      };
    }
    return {
      status: "manual",
      detail:
        "No known schema validation library found. Validation may be hand-written — review the body handling in your API endpoints.",
    };
  },
};

export const securityChecks: StandardsCheck[] = [
  stdRateLimit,
  stdAuthGuard,
  stdEnvProtection,
  stdHardcodedSecret,
  stdSecurityHeaders,
  stdSupabaseRls,
  stdInputValidation,
];
