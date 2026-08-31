/**
 * THE MEASUREMENT CONTRACT.
 *
 * In one run the tool's three most dangerous mistakes were all of one class: a
 * rule passed judgement on something it could not measure. It mistook Vercel's
 * challenge page for the application, looked for security headers in a 308
 * redirect response, hit an origin gate and declared "no rate limit". All three
 * were wrong, and all three looked CONFIDENT.
 *
 * The real defect is not in the individual rules but in the contract: when a
 * rule returns `[]` there is no way to tell "I looked and it is clean" from "I
 * could not look". Both are the same silence.
 *
 * The fix is not discipline — discipline gets forgotten. Every rule DECLARES
 * what it needs; the engine tests that need before running it. When it is unmet
 * the rule never runs and appears in the report as "not measured (reason)".
 * That way "clean" is only ever said about rules that actually looked.
 *
 * The declaration is MANDATORY: the registry test rejects a rule with no
 * `requires` field (an empty array is a valid declaration — "I have no preconditions").
 */

export type Requirement =
  /** The project must be a git repository (history and tracked-file rules). */
  | "git"
  /** A live URL must be defined and reachable. */
  | "live"
  /** package.json must exist (JS/TS dependency rules). */
  | "npm"
  /** Network access is required (npm audit, live probes). */
  | "net"
  /** At least one parseable JS/TS file must exist. */
  | "js"
  /** Must be a Python project (requirements/pyproject). */
  | "python"
  /** A SQL schema or migration file must exist. */
  | "sql";

/** A rule that did not run because a precondition was unmet. */
export interface CoverageGap {
  ruleId: string;
  ruleTitle: string;
  /** Which requirement was unmet. */
  requirement: Requirement;
  /** Human-readable reason. */
  reason: string;
}

export const REQUIREMENT_REASON: Record<Requirement, string> = {
  git: "not a git repository — history and tracked files cannot be read",
  live: "no live URL, or it does not respond",
  npm: "no package.json found",
  net: "no network access",
  js: "no parseable JS/TS file",
  python: "not a Python project (no requirements or pyproject)",
  sql: "no SQL schema or migration file",
};
