import { fileEvidence } from "../core/finding.js";
import type { StaticContext } from "../core/rule.js";
import type { StandardsCheck } from "./types.js";

/**
 * Standards profile — PERFORMANCE checks.
 * Source: the performance standard (a real case: iad1 + eu-west-1 + sequential
 * queries → 1.47s TTFB; 0.26s after the fix):
 * region alignment, hunting sequential queries, loading.tsx skeletons, narrowing select *.
 */

const norm = (f: string): string => f.replace(/\\/g, "/");

/** Exclude lockfiles and generated files. */
const isSourceFile = (file: string): boolean => {
  const f = norm(file);
  return !/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|.*\.min\.(js|css))$/.test(f);
};

const appPageFiles = (ctx: StaticContext): string[] =>
  ctx.files.filter((f) => /(^|\/)app\/(.*\/)?page\.(tsx|jsx|ts|js)$/.test(norm(f)));

// ---- 1. Vercel region alignment ----------------------------------------------

export const stdVercelRegion: StandardsCheck = {
  id: "std-perf-region",
  title: "Vercel region pinned (aligned with the database)",
  category: "performance",
  level: "warning",
  description:
    "Standard: the Vercel functions region equals the database region (every round trip across regions costs ~80ms). Looks for \"regions\" in vercel.json. The database region cannot be detected statically, so alignment is a manual check.",
  remediation:
    'Add your database\'s region to vercel.json, e.g. `"regions": ["fra1"]` (Supabase eu-central → fra1/dub1, us-east → iad1). Check the project region in the Supabase dashboard.',
  run(ctx) {
    const raw = ctx.read("vercel.json");
    if (raw == null) {
      return {
        status: "manual",
        detail:
          "No vercel.json. If this is deployed on Vercel, functions run in the default region (iad1) — with a European database every query crosses the Atlantic. Ignore if you do not deploy to Vercel.",
      };
    }
    let regions: unknown;
    try {
      regions = (JSON.parse(raw) as Record<string, unknown>).regions;
    } catch {
      regions = undefined;
    }
    if (Array.isArray(regions) && regions.length > 0) {
      return {
        status: "pass",
        detail: `Region pinned: ${regions.join(", ")}. Confirm manually that it matches the database region (not statically detectable).`,
        evidence: [fileEvidence("vercel.json", 1, `"regions": ${JSON.stringify(regions)}`)],
      };
    }
    return {
      status: "open",
      detail:
        "vercel.json exists but declares no \"regions\" — functions run in the default region (iad1). If the database lives elsewhere, every query pays ~80ms extra.",
      evidence: [fileEvidence("vercel.json", 1, '(no "regions" field)')],
    };
  },
};

// ---- 2. Sequential await chain (heuristic) ------------------------------------

const AWAIT_THRESHOLD = 5;

export const stdSequentialAwait: StandardsCheck = {
  id: "std-perf-sequential-await",
  title: "No sequential query chains per page",
  category: "performance",
  level: "info",
  description:
    `Standard: independent queries go through Promise.all — one page, one parallel batch. Heuristic: a page or route file with ${AWAIT_THRESHOLD} or more awaits and no Promise.all is flagged as suspicious (not certain — the awaits may genuinely depend on each other).`,
  remediation:
    "Count the await chain on the page and parallelise independent queries with `const [a, b, c] = await Promise.all([...])`. Collapse repeated auth/role lookups with React cache(). Prove the fix with a TTFB measurement.",
  run(ctx) {
    const targets = ctx.files.filter((f) => {
      const n = norm(f);
      return (
        /(^|\/)app\/.*\/(page|layout|route)\.(tsx|jsx|ts|js)$/.test(n) ||
        /(^|\/)app\/(page|layout)\.(tsx|jsx|ts|js)$/.test(n) ||
        /(^|\/)pages\/.*\.(tsx|jsx|ts|js)$/.test(n)
      );
    });
    if (targets.length === 0) {
      return { status: "na", detail: "No page or route files found (no Next.js app/pages structure)." };
    }
    const suspects: Array<{ file: string; awaits: number; line: number }> = [];
    for (const file of targets) {
      const content = ctx.read(file);
      if (!content) continue;
      const awaits = (content.match(/\bawait\s/g) ?? []).length;
      if (awaits >= AWAIT_THRESHOLD && !/Promise\.all(Settled)?\s*\(/.test(content)) {
        const line = content.split(/\r?\n/).findIndex((l) => /\bawait\s/.test(l)) + 1;
        suspects.push({ file, awaits, line: Math.max(1, line) });
      }
    }
    if (suspects.length === 0) {
      return {
        status: "pass",
        detail: `No suspicious await chain in ${targets.length} page/route file(s) (threshold: ${AWAIT_THRESHOLD} awaits without Promise.all).`,
      };
    }
    suspects.sort((a, b) => b.awaits - a.awaits);
    return {
      status: "manual",
      detail:
        `${suspects.length} file(s) have ${AWAIT_THRESHOLD}+ awaits and no Promise.all: ` +
        suspects.slice(0, 5).map((s) => `${norm(s.file)} (${s.awaits} await)`).join(", ") +
        ". Parallelise them if they are independent; ignore if they are genuinely sequential (heuristic check).",
      evidence: suspects.slice(0, 5).map((s) => fileEvidence(s.file, s.line, `${s.awaits} await, Promise.all yok`)),
    };
  },
};

// ---- 3. loading.tsx iskeletleri -----------------------------------------------

export const stdLoadingSkeleton: StandardsCheck = {
  id: "std-perf-loading",
  title: "loading.tsx iskeletleri var",
  category: "performance",
  level: "warning",
  description:
    "Standard: every route ships a loading.tsx skeleton — perceived speed matters and a blank screen is never acceptable. Counts loading files in a Next.js app router project.",
  remediation:
    "Add loading.tsx under app/ (at least at the root and in data-fetching route groups) and render a skeleton — the Suspense boundary is created for you.",
  run(ctx) {
    const pages = appPageFiles(ctx);
    if (ctx.project.stack.framework !== "next" || pages.length === 0) {
      return { status: "na", detail: "No Next.js app router structure detected." };
    }
    const loadings = ctx.files.filter((f) => /(^|\/)app\/(.*\/)?loading\.(tsx|jsx|ts|js)$/.test(norm(f)));
    if (loadings.length === 0) {
      return {
        status: "open",
        detail: `The app router has ${pages.length} page(s) and no loading.tsx at all — users stare at a blank screen while server queries run.`,
        evidence: [fileEvidence("app/loading.tsx", 1, "(dosya yok)")],
      };
    }
    return {
      status: "pass",
      detail: `${loadings.length} loading file(s) found for ${pages.length} page(s). Check that every data-fetching route group is covered.`,
      evidence: [fileEvidence(loadings[0], 1, norm(loadings[0]))],
    };
  },
};

// ---- 4. select * daraltma ------------------------------------------------------

const SELECT_STAR =
  /\.select\(\s*["'`]\*["'`]\s*\)|\bSELECT\s+\*\s+FROM\b/i;

export const stdSelectStar: StandardsCheck = {
  id: "std-perf-select-star",
  title: "No select * on heavy list queries",
  category: "performance",
  level: "info",
  description:
    "Standard: narrow `select *` on heavy lists and take counts with head+count. Looks for .select('*') and SQL SELECT * in the code.",
  remediation:
    "Select only the columns you need: `.select(\"id, name, created_at\")`. To count rows use `select(\"*\", { count: \"exact\", head: true })`.",
  run(ctx) {
    const hits = ctx.grep(SELECT_STAR, (f) => /\.(ts|tsx|js|jsx|mjs|cjs|sql)$/.test(f) && isSourceFile(norm(f)));
    if (hits.length === 0) {
      return { status: "pass", detail: "No select('*') or SELECT * usage found." };
    }
    return {
      status: "open",
      detail: `select * is used in ${hits.length} place(s). Harmless on small tables — narrow the ones behind heavy list queries.`,
      evidence: hits.slice(0, 5).map((h) => fileEvidence(h.file, h.line, h.text)),
    };
  },
};

export const performanceChecks: StandardsCheck[] = [
  stdVercelRegion,
  stdSequentialAwait,
  stdLoadingSkeleton,
  stdSelectStar,
];
