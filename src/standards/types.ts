import type { Evidence } from "../core/finding.js";
import type { StaticContext } from "../core/rule.js";

/**
 * The standards profile — separate from the OWASP rules, this turns a written
 * set of security and performance standards into concrete static checks.
 *
 *
 * How it differs from OWASP findings: every check ALWAYS produces a result
 * (pass / open / manual / na) — so the report reads like a checklist rather
 * than only a list of errors.
 */

/**
 * The third category: "integrity".
 *
 * Security asks "can someone get in", performance asks "how long does it take".
 * Integrity asks something else: **is the system telling the truth about
 * itself?** None of the 13 failures found in one audit fell under the first two.
 *
 * Most items in this category are deliberately "manual": part of an audit list
 * cannot be automated (a button in a provider dashboard, whether a negative test
 * was actually run). Keeping the non-automatable items VISIBLE, instead of
 * dropping them from the list, is what stops them being forgotten.
 */
export type StandardsCategory = "security" | "performance" | "integrity";

/** Check level. Heuristic checks that are not conclusive are never SHOWN as critical. */
export type StandardsLevel = "critical" | "warning" | "info";

/**
 * Kontrol sonucu:
 *  - "pass"   → the standard is met.
 *  - "open"   → the standard is not met (evidenced, high confidence).
 *  - "manual" → there is a heuristic signal but it is not conclusive — verify by hand.
 *  - "na"     → not meaningful for this project (e.g. RLS without Supabase).
 */
export type StandardsStatus = "pass" | "open" | "manual" | "na";

/** A check's run() output — the meta fields are added by the runner. */
export interface StandardsCheckOutcome {
  status: StandardsStatus;
  /** Human-readable explanation: why it passed, why it is open, what to verify. */
  detail: string;
  evidence?: Evidence[];
  /** Level override based on the finding (default: the check's own level). */
  level?: StandardsLevel;
}

export interface StandardsCheck {
  id: string;
  title: string;
  category: StandardsCategory;
  level: StandardsLevel;
  /** What the check looks for (the standard itself). */
  description: string;
  /** How to fix it when it is open. */
  remediation: string;
  run(ctx: StaticContext): StandardsCheckOutcome | Promise<StandardsCheckOutcome>;
}

/** A single check result written to the report. */
export interface StandardsCheckResult {
  id: string;
  title: string;
  category: StandardsCategory;
  level: StandardsLevel;
  status: StandardsStatus;
  detail: string;
  remediation: string;
  evidence: Evidence[];
}

export interface StandardsStatusCounts {
  pass: number;
  open: number;
  manual: number;
  na: number;
}

export interface StandardsCategorySummary extends StandardsStatusCounts {
  /** 0-100 health score (higher is better). */
  score: number;
}

/** The profile block added to the JSON report (backwards-compatible, optional). */
export interface StandardsResult {
  profile: "nocturn-standards";
  version: 1;
  /** 0-100 overall health score (higher is better). */
  score: number;
  counts: StandardsStatusCounts;
  categories: Record<StandardsCategory, StandardsCategorySummary>;
  checks: StandardsCheckResult[];
}
