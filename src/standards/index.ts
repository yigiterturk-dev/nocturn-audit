import type { StaticContext } from "../core/rule.js";
import type {
  StandardsCategory,
  StandardsCategorySummary,
  StandardsCheck,
  StandardsCheckResult,
  StandardsLevel,
  StandardsResult,
  StandardsStatusCounts,
} from "./types.js";
import { securityChecks } from "./security.js";
import { performanceChecks } from "./performance.js";
import { integrityChecks } from "./integrity.js";

export type {
  StandardsCategory,
  StandardsCheck,
  StandardsCheckResult,
  StandardsLevel,
  StandardsResult,
  StandardsStatus,
} from "./types.js";

/** The active standards check set (security + performance). */
export const standardsChecks: StandardsCheck[] = [
  ...securityChecks,
  ...performanceChecks,
  ...integrityChecks,
];

/**
 * The score penalty of an open check, by level.
 * "manual" carries no penalty (a false positive should not lower the score — it just stays visible).
 */
const FAIL_PENALTY: Record<StandardsLevel, number> = {
  critical: 25,
  warning: 10,
  info: 3,
};

function emptyStatusCounts(): StandardsStatusCounts {
  return { pass: 0, open: 0, manual: 0, na: 0 };
}

function summarize(results: StandardsCheckResult[]): StandardsCategorySummary {
  const counts = emptyStatusCounts();
  let penalty = 0;
  for (const r of results) {
    counts[r.status]++;
    if (r.status === "open") penalty += FAIL_PENALTY[r.level];
  }
  return { ...counts, score: Math.max(0, Math.min(100, 100 - penalty)) };
}

/**
 * Runs the standards profile. Every check always produces a result; a check that
 * throws is marked "manual" (the scan does not fall over).
 */
export async function runStandards(ctx: StaticContext): Promise<StandardsResult> {
  const checks: StandardsCheckResult[] = [];
  for (const check of standardsChecks) {
    try {
      const out = await Promise.resolve(check.run(ctx));
      checks.push({
        id: check.id,
        title: check.title,
        category: check.category,
        level: out.level ?? check.level,
        status: out.status,
        detail: out.detail,
        remediation: check.remediation,
        evidence: out.evidence ?? [],
      });
    } catch (err) {
      checks.push({
        id: check.id,
        title: check.title,
        category: check.category,
        level: check.level,
        status: "manual",
        detail: `The check threw while running: ${err instanceof Error ? err.message : String(err)} — verify by hand.`,
        remediation: check.remediation,
        evidence: [],
      });
    }
  }

  const byCat = (cat: StandardsCategory) =>
    summarize(checks.filter((c) => c.category === cat));
  const overall = summarize(checks);

  return {
    profile: "nocturn-standards",
    version: 1,
    score: overall.score,
    counts: {
      pass: overall.pass,
      open: overall.open,
      manual: overall.manual,
      na: overall.na,
    },
    categories: {
      security: byCat("security"),
      performance: byCat("performance"),
      integrity: byCat("integrity"),
    },
    checks,
  };
}
