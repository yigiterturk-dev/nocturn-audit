import type { AstFile } from "./ast.js";
import type { Confidence, Finding, OwaspCategory } from "./finding.js";
import type { Severity } from "./severity.js";
import type { Requirement } from "./measurement.js";

/** A project's entry in targets.json. */
export interface Project {
  name: string;
  /** Absolute, expanded (tilde resolved) path. */
  path: string;
  url?: string;
  owned: boolean;
  stack: Stack;
}

export interface Stack {
  // THE TYPE MUST MATCH REALITY. `db` only knew the Postgres family, while
  // targets.json contained projects scanned as `flask/sqlite`, and the rules
  // that detect the engine did not recognise them at all. A missing type means
  // a rule that silently does nothing.
  framework?: "next" | "vite" | "node" | "flask" | "django" | "express" | "unknown";
  db?: "supabase" | "neon" | "postgres" | "prisma" | "sqlite" | "mysql" | "unknown";
  auth?: "clerk" | "supabase" | "next-auth" | "custom" | "unknown";
}

export interface GrepMatch {
  file: string;
  line: number;
  column: number;
  text: string;
}

/**
 * Static rule context — helpers for reading code.
 */
export interface StaticContext {
  project: Project;
  /** Project root directory (absolute). */
  root: string;
  /** Scannable source files, relative to the root. */
  files: string[];
  /** Relative path → contents (null when missing). */
  read(relPath: string): string | null;
  /**
   * Line-based search with a regex.
   * @param regex applied to every line (the global flag is added automatically)
   * @param include only search files matching this predicate (optional)
   */
  grep(regex: RegExp, include?: (file: string) => boolean): GrepMatch[];
  /**
   * The file's syntax tree (JS/TS only), or null.
   *
   * CACHED: when several rules ask for the same file, it is parsed once.
   * Parsing per rule would have meant a slowdown directly proportional to the
   * number of rules that moved to the tree.
   */
  ast(relPath: string): AstFile | null;
  /**
   * Reads ONLY the first `bytes` bytes of the file.
   *
   * Data files (CSV/JSONL) can be hundreds of megabytes, and pulling one
   * entirely into memory is pointless: the personal-data rule needs the header
   * row and a few sample lines.
   */
  readHead(relPath: string, bytes?: number): string | null;
  /** Does a given file exist. */
  exists(relPath: string): boolean;
  /**
   * Is the file tracked by git (git ls-files)?
   * Returns false when this is not a git repository, or the file is untracked.
   * Used by the secret and `.env` rules to tell "actually committed" apart.
   */
  isTracked(relPath: string): boolean;
  /** Is the project a git worktree (i.e. is isTracked meaningful)? */
  isGitRepo: boolean;
}

/** Result of a live probe (used to build evidence). */
export interface ProbeResult {
  ok: boolean;
  url: string;
  method: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  bodySnippet: string;
  /** Human-readable request summary (evidence). */
  requestLine: string;
  /** Human-readable response summary (evidence). */
  responseLine: string;
  error?: string;
}

/**
 * Live rule context — runs only for owned:true projects.
 * Every probe is low intensity and non-destructive.
 */
export interface LiveContext {
  project: Project;
  baseUrl: string;
  /**
   * Non-destructive HTTP probe. Supports GET/HEAD/POST.
   * Does not follow redirects (we want to see the chain as evidence).
   */
  probe(path: string, init?: RequestInit): Promise<ProbeResult>;
}

/** Context for the npm audit wrapper. */
export interface DepsContext {
  project: Project;
  root: string;
  exists(relPath: string): boolean;
}

export type RuleKind = "static" | "live" | "deps";

interface BaseRule {
  /**
   * Should this rule also scan TEST and FIXTURE files?
   *
   * Default `false`: test data is not production surface, and a fake key in a
   * fixture is a scenario, not a leak. Only rules that compare a list against
   * the directory (e.g. the one measuring whether test files are counted) set
   * bunu `true` yapar.
   */
  scansTests?: boolean;

  /**
   * Should this rule see COMMENTS and pattern definitions?
   *
   * Default `false`: comments and regex literals are blanked out (line and
   * column numbers are preserved). Only rules that search for the text itself
   * (e.g. the one reading a "GENERATED FILE" banner) set this to `true`.
   * bunu `true` yapar.
   */
  scansComments?: boolean;
  id: string;
  title: string;
  owasp: OwaspCategory;
  /** Base severity — a finding may override it. */
  severity: Severity;
  kind: RuleKind;
  description?: string;
  /** Related CWE id (e.g. "CWE-311"). Backwards-compatible, optional. */
  cwe?: string;
  /**
   * The rule's default confidence. When a finding does not set its own
   * belirtmezse engine bunu (o da yoksa "likely") atar. Geriye-uyumlu, opsiyonel.
   */
  confidence?: Confidence;
  /**
   * PRECONDITIONS — what does this rule need in order to measure anything?
   *
   * The declaration is MANDATORY (an empty array is valid: "no preconditions").
   * When a requirement is unmet the engine DOES NOT RUN the rule and the report
   * shows it as "not measured". A `[]` return then means exactly one thing:
   *
   * See `core/measurement.ts` for why this is a contract rather than discipline.
   */
  requires: Requirement[];
}

export interface StaticRule extends BaseRule {
  kind: "static";
  run(ctx: StaticContext): Finding[] | Promise<Finding[]>;
}

export interface LiveRule extends BaseRule {
  kind: "live";
  run(ctx: LiveContext): Promise<Finding[]>;
}

export interface DepsRule extends BaseRule {
  kind: "deps";
  run(ctx: DepsContext): Promise<Finding[]>;
}

export type Rule = StaticRule | LiveRule | DepsRule;
