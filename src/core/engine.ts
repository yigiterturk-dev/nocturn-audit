import { closeSync, existsSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join, relative, sep } from "node:path";
import fg from "fast-glob";
import type { Finding } from "./finding.js";
import { fileEvidence } from "./finding.js";
import {
  emptyCounts,
  riskScore,
  pislikSkoru,
  type Pislik,
  type SeverityCounts,
} from "./severity.js";
import type {
  DepsContext,
  GrepMatch,
  LiveContext,
  ProbeResult,
  Project,
  Rule,
  StaticContext,
} from "./rule.js";
import { runStandards } from "../standards/index.js";
import type { StandardsResult } from "../standards/types.js";
import { isTestOrFixture } from "./test-files.js";
import { ayristir, type AstFile } from "./ast.js";
import { REQUIREMENT_REASON, type Requirement, type CoverageGap } from "./measurement.js";
import { isInsideRegexLiteral } from "./regex-literal.js";
import { blankNonCode } from "./sanitize.js";
import { measureCoverage, type CoverageReport } from "./coverage.js";

export interface ProjectReport {
  project: Project;
  findings: Finding[];
  counts: SeverityCounts;
  /**
   * Severity counts split by confidence (backwards-compatible extra field).
   * `certain` = deterministic findings, `heuristic` = likely (heuristic) ones.
   * Their totals match `counts` exactly.
   */
  certainCounts: SeverityCounts;
  heuristicCounts: SeverityCounts;
  score: number;
  /**
   * PİSLİK SKORU — 0-100 karşılaştırılabilir kirlilik + kısmi-ölçüm dürüstlüğü.
   * gaps > 0 ise skor bir ALT SINIRDIR; rapor bunu "kısmi ölçüm" ile söyler.
   */
  pislik: Pislik;
  /** Ids of the rules that ran. */
  rulesRun: string[];
  /** Atlanan reason (varsa). */
  notes: string[];
  /**
   * CONTENT DIGEST OF THE FILES BEHIND FINDINGS (path → first 16 hex of sha256).
   *
   * Why: when a finding disappeared between two runs, there was no way to tell
   * "the hole was closed" from "detection was lost". That happened exactly once:
   * three lines were added to a project, an SSRF finding vanished, and everyone
   * assumed it was fixed — the rule's ±6 line window had shifted and the hole
   * was still there.
   * The digest makes the distinction possible: if the finding is gone but the
   * file NEVER CHANGED, what got fixed is the rule, not the code.
   */
  fileDigests: Record<string, string>;
  /**
   * MEASUREMENT GAPS — rules that never ran because a precondition was unmet.
   *
   * This list is the most honest part of the report: the only place that says
   * "I did not look at this". A rule returning `[]` now means only "I looked and
   * it was clean"; a rule that could not look lands here.
   */
  gaps: CoverageGap[];
  /**
   * Result of the standards profile (security + performance checklist).
   * Produced whenever a static scan runs. Backwards-compatible and optional —
   * it is NOT included in the OWASP finding counts or the risk score.
   */
  standards?: StandardsResult;
  /**
   * How much of the project the tool was able to READ.
   *
   * Saying "no findings" for a language it cannot read is the worst way to give
   * false confidence. The report has to state its coverage.
   */
  coverage?: CoverageReport;
}

export interface ScanOptions {
  /** Sadece statik kurallar. */
  staticOnly?: boolean;
  /** Live rules only. */
  liveOnly?: boolean;
  /** Run the dependency rules (default: yes unless staticOnly/liveOnly). */
  includeDeps?: boolean;
  /** Run the standards profile (default: yes when a static scan runs). */
  includeStandards?: boolean;
}

const SOURCE_GLOBS = [
  "**/*.{ts,tsx,js,jsx,mjs,cjs}",
  // Python and other backend languages: the tool used to scan only JS/TS, so
  // Flask/Django/FastAPI projects were ENTIRELY invisible and "no findings"
  // silently meant "did not look". The Python rules (SQL injection,
  // busy_timeout, spoofable IP) only run once these files are read.
  //
  "**/*.{py,rb,go,rs,php,java,kt}",
  // `.txt` is DELIBERATELY absent: it is not source, and in a repository it is
  // usually a frozen schema or data dump. When it was included, a single
  // `.ts.txt` file produced 123 false findings. The real leak case was `.md`.
  "**/*.{json,env,md,mdx,yml,yaml,toml,ini,conf,sh,bash,zsh}",
  // Tool histories and logs: the MOST COMMON path for a leak.
  //
  // In a real incident an API key was passed with `aider --api-key`, written
  // into the tool's chat history file (`.aider.chat.history.md`), and committed
  // with `git add -A`. The repository was public; the key was used and the
  // account balance went negative.
  //
  // `.md` was NOT among the scanned extensions — only `.mdx` was. So the tool
  // could not have seen the very leak that actually happened to its user.
  "**/.*history*",
  // Data files: their headers are inspected for the personal-data rule.
  // They are not read in full (`ctx.readHead`), only the first few kilobytes.
  "**/*.{csv,tsv,jsonl,ndjson}",
  // SQL schemas and migrations plus the Prisma schema (for the RLS and plaintext-data rules)
  "**/*.{sql,prisma}",
  // HTML files (for the SRI / external script rule)
  "**/*.{html,htm}",
  "next.config.{js,ts,mjs,cjs}",
  "vite.config.{js,ts}",
  ".env*",
  ".gitignore",
  "package.json",
];

const IGNORE_GLOBS = [
  "**/node_modules/**",
  "**/dist/**",
  // Other names for build output. `dist/` was excluded but `dist-electron/`,
  // `out-tsc/` and `release/` were not — one project's Electron output was
  // scanned and produced findings a second time alongside its own source (the
  // same bug counted twice, and not where it should be fixed).
  "**/dist-*/**",
  "**/out-*/**",
  "**/release/**",
  "**/.output/**",
  "**/.svelte-kit/**",
  "**/storybook-static/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/.git/**",
  "**/out/**",
  "**/report/**", // do not scan the tool's own report output
  "**/corpus/**", // the tool's own corpus DATA (labels.json / bug-db.json —
                  // it holds snippets of scanned code as strings, and produced
                  // CERTAIN false positives when dogfooding: patterns such as
                  // dangerouslySetInnerHTML/CORS). Data, not code.
  // THIRD-PARTY / vendor code: the project did not write it and cannot fix it.
  //
  // `node_modules` was excluded from the start, but the equivalents in other
  // ecosystems were not. Scanning a Python project, two of four findings came
  // from inside `venv/lib/python3.11/site-packages/...` — urllib3's own code.
  // A finding the user cannot fix is not a finding, it is noise.
  "**/venv/**",
  "**/.venv/**",
  "**/site-packages/**",
  "**/vendor/**",
  "**/.tox/**",
  "**/__pycache__/**",
  "**/target/**",   // rust/java
  "**/.gradle/**",
  "**/Pods/**",     // ios
  "**/.vercel/**",
  "**/.turbo/**",
  "**/.cache/**",
  // Minified / bundled vendor code — not written here, not fixable here; and
  // minified JS contains every pattern (eval/child_process/SQL) → an FP factory.
  "**/*.min.js",
  "**/*.min.css",
  "**/*.bundle.js",
  "**/*-min.js",
];

// Is this a minified/bundled file? (the name has no .min but the contents are
// minified — e.g. a self-hosted tailwind-3.4.17.js). Heuristic: in JS/CSS, if
// the LONGEST line in the first 8KB exceeds 1000 characters, treat it as
// minified. Vendor code is not project code, and it contains every pattern.
function esMinified(absPath: string): boolean {
  if (!/\.(js|mjs|cjs|css)$/i.test(absPath)) return false;
  try {
    const bas = readFileSync(absPath, "utf-8").slice(0, 8192);
    let enUzun = 0, gecerli = 0;
    for (const line of bas.split("\n")) {
      if (line.length > enUzun) enUzun = line.length;
      gecerli++;
    }
    // One enormous line, or a very long average line → minified.
    return enUzun > 1000 || (gecerli > 0 && bas.length / gecerli > 400);
  } catch {
    return false;
  }
}

/**
 * Is this the tool's OWN repository? (dogfood)
 *
 * When nocturn-audit scans itself, RULE DEFINITION files such as
 * `src/static/*.ts` and `src/live/*.ts` get scanned. Those files carry the
 * pattern they search for, and a description of it, as strings — the rule's own
 * bait sits in the rule's own source. In one run the single "high" finding was
 * exactly this: the DESCRIPTION TEXT inside `src/static/sql-injection.ts:96`
 * about SQL built by concatenation was read as SQL injection. Likewise two
 * medium "Supabase service_role usage" findings came from `missing-rls.ts`'s own
 * patterns. All of them certain false positives.
 *
 * Rule source behaves like data (see the `corpus/` exception): it holds the
 * patterns of scanned code as strings. So the tool's own rule directories are
 * excluded during a dogfood scan — and ONLY in the tool's own repository.
 * Another project's `src/static/` directory is scanned normally.
 */
function kendiDeposuMu(root: string): boolean {
  try {
    const pj = JSON.parse(readFileSync(join(root, "package.json"), "utf-8"));
    return pj?.name === "nocturn-audit";
  } catch {
    return false;
  }
}

/** The tool's own rule-definition directories — they hold bait when dogfooding. */
const RULE_SOURCE_GLOBS = [
  "src/static/**",
  "src/live/**",
  "src/deps/**",
  "src/integrity/**",
  "src/standards/**",
  "src/rules.ts",
  "src/invariants.ts",
];

/**
 * Does this process have network access?
 *
 * The `net` requirement used to be declared but NEVER measured — `hasNetwork`
 * was hardcoded to `true`, so a rule that needed the network ran (and usually
 * threw) even when there was none. That is the exact silence the measurement
 * contract exists to prevent. This does one cheap, cached HEAD request; the
 * result is shared by every project in the process.
 */
let netCache: boolean | null = null;
async function hasNetworkAccess(): Promise<boolean> {
  if (netCache !== null) return netCache;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2_500);
  try {
    const res = await fetch("https://registry.npmjs.org/", {
      method: "HEAD",
      signal: controller.signal,
    });
    netCache = res.ok || res.status < 500;
  } catch {
    netCache = false;
  } finally {
    clearTimeout(timer);
  }
  return netCache;
}

/** Collect a project's source files (relative to the root). */
export async function collectFiles(root: string): Promise<string[]> {
  if (!existsSync(root)) return [];
  const ignore = kendiDeposuMu(root)
    ? [...IGNORE_GLOBS, ...RULE_SOURCE_GLOBS]
    : IGNORE_GLOBS;
  const files = await fg(SOURCE_GLOBS, {
    cwd: root,
    ignore,
    dot: true,
    onlyFiles: true,
    suppressErrors: true,
    followSymbolicLinks: false,
  });
  // SIZE LIMIT. When the scanned extensions were widened (md/txt/yml/log) a scan
  // went past ten minutes and the tool became unusable — a self-inflicted
  // regression. Source files are not megabytes; anything that big is data or a
  // log, and the rules already read those from the head with `readHead`.
  const VERI = /\.(csv|tsv|jsonl|ndjson)$/i;
  const SINIR = 2 * 1024 * 1024;
  const VERI_SINIRI = 512 * 1024 * 1024;

  const uygun: string[] = [];
  for (const f of files) {
    try {
      const boyut = statSync(join(root, f)).size;
      const boyutTamam = VERI.test(f) ? boyut <= VERI_SINIRI : boyut <= SINIR;
      if (boyutTamam && !esMinified(join(root, f))) uygun.push(f);
    } catch {
      // Okunamayan dosya listeye girmez.
    }
  }
  return uygun.map((f) => f.split("/").join(sep));
}

/**
 * Returns the posix-normalised set of files tracked by git.
 * Returns `null` when this is not a git repository (no tracking information).
 */
export function collectTrackedFiles(root: string): Set<string> | null {
  try {
    const out = execFileSync("git", ["ls-files", "-z"], {
      cwd: root,
      timeout: 15_000,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    }).toString("utf8");
    const set = new Set<string>();
    for (const f of out.split("\0")) {
      const p = f.trim();
      if (p) set.add(p);
    }
    return set;
  } catch {
    return null;
  }
}

/**
 * Caches shared between the sanitized static contexts (ctx / tamCtx).
 *
 * The engine builds THREE contexts per project. Each used to carry its own
 * read + AST cache, so the same file was read and parsed up to three times.
 * The sanitized contexts (ctx, tamCtx) can share one cache safely — they
 * differ only in the file LIST, not in how a given file is read. rawCtx keeps
 * its own cache because it reads UNSANITIZED content (sharing would hand
 * sanitized text to the comment-scanning rules).
 */
interface SharedCaches {
  readCache: Map<string, string | null>;
  treeCache: Map<string, AstFile | null>;
}

function buildStaticContext(
  project: Project,
  root: string,
  files: string[],
  tracked: Set<string> | null,
  /** Blank out comments and pattern definitions (line/column preserved). */
  sanitize = false,
  shared?: SharedCaches,
): StaticContext {
  const cache = shared?.readCache ?? new Map<string, string | null>();
  const read = (relPath: string): string | null => {
    if (cache.has(relPath)) return cache.get(relPath)!;
    const abs = join(root, relPath);
    let content: string | null = null;
    try {
      if (existsSync(abs)) content = readFileSync(abs, "utf8");
    } catch {
      content = null;
    }
    if (content != null && sanitize && /\.(ts|tsx|js|jsx|mjs|cjs|sql)$/.test(relPath)) {
      content = blankNonCode(content);
    }
    cache.set(relPath, content);
    return content;
  };

  const readHead = (relPath: string, bytes = 64 * 1024): string | null => {
    const abs = join(root, relPath);
    let fd: number | null = null;
    try {
      if (!existsSync(abs)) return null;
      fd = openSync(abs, "r");
      const tampon = Buffer.alloc(bytes);
      const readable = readSync(fd, tampon, 0, bytes, 0);
      return tampon.subarray(0, readable).toString("utf8");
    } catch {
      return null;
    } finally {
      if (fd !== null) { try { closeSync(fd); } catch { /* yok say */ } }
    }
  };

  const exists = (relPath: string): boolean => existsSync(join(root, relPath));

  const grep = (
    regex: RegExp,
    include?: (file: string) => boolean,
  ): GrepMatch[] => {
    const matches: GrepMatch[] = [];
    const flags = regex.flags.includes("g")
      ? regex.flags
      : regex.flags + "g";
    // Compile ONCE, not once per line. The old code rebuilt the RegExp inside
    // the line loop — with ~60 rules × thousands of files × lines each, that
    // was a measurable share of scan time.
    const rx = new RegExp(regex.source, flags);
    for (const file of files) {
      if (include && !include(file)) continue;
      const content = read(file);
      if (content == null) continue;
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        let m: RegExpExecArray | null;
        while ((m = rx.exec(lines[i])) !== null) {
          // A match inside a pattern definition is skipped: `/child_process/` is
          // a detector, not a call. Every project with an input validator or a
          // log scrubber contains this shape.
          if (!isInsideRegexLiteral(lines[i], m.index)) {
            matches.push({
              file,
              line: i + 1,
              column: m.index + 1,
              text: lines[i],
            });
          }
          if (m.index === rx.lastIndex) rx.lastIndex++;
        }
      }
    }
    return matches;
  };

  const isTracked = (relPath: string): boolean => {
    if (!tracked) return false;
    return tracked.has(relPath.replace(/\\/g, "/"));
  };

  // Tree cache: ONE parse per file. `null` is cached too, so an unparseable
  // file is not retried by every rule.
  const treeCache = shared?.treeCache ?? new Map<string, AstFile | null>();
  const ast = (relPath: string): AstFile | null => {
    if (treeCache.has(relPath)) return treeCache.get(relPath) ?? null;
    const content = read(relPath);
    const result = content === null ? null : ayristir(relPath, content);
    treeCache.set(relPath, result);
    return result;
  };

  return {
    project,
    root,
    files,
    read,
    readHead,
    grep,
    exists,
    isTracked,
    ast,
    isGitRepo: tracked !== null,
  };
}

/**
 * Is this a bot/WAF challenge page?
 *
 * In one run the live probes produced 28 "high" findings — "health endpoint
 * returns an error" for four separate projects. Every one was false.
 * What actually happened: Vercel deployment protection answered every request
 * with 403 and a "Vercel Security Checkpoint" HTML page
 * (`x-vercel-mitigated: challenge`). The tool was measuring the challenge page,
 * not the application.
 *
 * This is not one rule's problem: once a challenge sits in front, security
 * headers, open endpoints, user enumeration — EVERY live rule reads the
 * challenge page. A check that reports findings for what it could not measure
 * is worse than one that says "clean".
 */
export function challengeMi(
  status: number,
  headers: Record<string, string>,
  body: string,
): string | null {
  const h = (k: string) => (headers[k] ?? headers[k.toLowerCase()] ?? "").toLowerCase();
  if (h("x-vercel-mitigated") === "challenge" || h("x-vercel-challenge-token"))
    return "Vercel deployment protection (challenge)";
  if (h("cf-mitigated") === "challenge") return "Cloudflare challenge";
  const b = body.toLowerCase();
  if (status === 403 || status === 503) {
    if (b.includes("vercel security checkpoint")) return "Vercel Security Checkpoint";
    if (b.includes("cf-browser-verification") || b.includes("just a moment"))
      return "Cloudflare bot protection";
    if (b.includes("attention required") && b.includes("cloudflare"))
      return "Cloudflare bot protection";
  }
  return null;
}

/**
 * Does the base URL return a redirect?
 *
 * One project was registered as `http://…sslip.io` while Caddy 308'd every
 * request to https. Because probes run with `redirect: "manual"`, EVERY live
 * rule measured the 308 response: "no CSP", "no X-Frame-Options", "no rate
 * limit on login"… all five were false — every header was present on https.
 * Looking for headers in a redirect response is like judging the furniture by
 * staring at a closed door.
 *
 * The manual redirect behaviour is PRESERVED (the open-redirect rule depends
 * on it); only the BASE URL is normalised once, by following a permanent
 * redirect that stays on the same host.
 */
export function redirectTarget(baz: string, result: ProbeResult): string | null {
  if (!result.ok || result.status < 300 || result.status > 399) return null;
  const loc = result.headers["location"] ?? result.headers["Location"];
  if (!loc) return null;
  try {
    const target = new URL(loc, baz);
    const source = new URL(baz);
    // Only the same host (adding or dropping www does not count — the host must
    // match exactly), and only a scheme upgrade or path simplification. A
    // redirect to another host may not be the thing we meant to measure.
    if (target.hostname !== source.hostname) return null;
    // ONLY an origin change (scheme/port) is followed. Treating a PATH redirect
    // such as `/` → `/login` as the new base would be a disaster: every later
    // probe would go to a non-existent address like `/login/api/health` and
    // everything would look like a 404. One host did exactly this (302 → /login).
    if (target.origin === source.origin) return null;
    return target.origin;
  } catch {
    return null;
  }
}

function buildLiveContext(project: Project): LiveContext {
  const baseUrl = (project.url ?? "").replace(/\/$/, "");

  const probe = async (
    path: string,
    init?: RequestInit,
  ): Promise<ProbeResult> => {
    const url = path.startsWith("http")
      ? path
      : baseUrl + (path.startsWith("/") ? path : "/" + path);
    const method = (init?.method ?? "GET").toUpperCase();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12_000);
    try {
      const res = await fetch(url, {
        ...init,
        method,
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "user-agent": "nocturn-audit/0.1 (+detection-only)",
          ...(init?.headers ?? {}),
        },
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k] = v));
      let body = "";
      try {
        body = (await res.text()).slice(0, 2000);
      } catch {
        body = "";
      }
      const requestLine = `${method} ${url}`;
      const responseLine =
        `HTTP ${res.status} ${res.statusText}\n` +
        Object.entries(headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n");
      return {
        ok: true,
        url,
        method,
        status: res.status,
        statusText: res.statusText,
        headers,
        bodySnippet: body,
        requestLine,
        responseLine,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        url,
        method,
        status: 0,
        statusText: "",
        headers: {},
        bodySnippet: "",
        requestLine: `${method} ${url}`,
        responseLine: `ERROR: ${message}`,
        error: message,
      };
    } finally {
      clearTimeout(timer);
    }
  };

  return { project, baseUrl, probe };
}

function tallyCounts(findings: Finding[]): SeverityCounts {
  const counts = emptyCounts();
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** Splits findings by confidence and produces the severity counts. */
function tallyByConfidence(findings: Finding[]): {
  certain: SeverityCounts;
  heuristic: SeverityCounts;
} {
  const certain = emptyCounts();
  const heuristic = emptyCounts();
  for (const f of findings) {
    if (f.confidence === "certain") certain[f.severity]++;
    else heuristic[f.severity]++;
  }
  return { certain, heuristic };
}

/**
 * Scan a single project. Runs each rule with the context matching its kind.
 * Live rules run ONLY when the project is owned:true and has a url.
 */
/**
 * Are the requirements met? Returns the FIRST unmet requirement.
 *
 * This is what makes a "silent clean" impossible: before a rule runs we check
 * whether the environment it needs exists. If it does not, the rule is NEVER
 * run and appears in the report as "not measured" — rather than returning `[]`
 * and being mistaken for clean.
 */
function unmetRequirement(
  gerekenler: Requirement[],
  ortam: {
    gitDeposu: boolean;
    files: string[];
    root: string;
    hasLive: boolean;
    hasNetwork: boolean;
  },
): Requirement | null {
  for (const g of gerekenler) {
    if (g === "git" && !ortam.gitDeposu) return g;
    if (g === "live" && !ortam.hasLive) return g;
    if (g === "net" && !ortam.hasNetwork) return g;
    if (g === "npm" && !existsSync(join(ortam.root, "package.json"))) return g;
    if (g === "js" && !ortam.files.some((f) => /\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/i.test(f)))
      return g;
    if (
      g === "python" &&
      !existsSync(join(ortam.root, "requirements.txt")) &&
      !existsSync(join(ortam.root, "pyproject.toml"))
    )
      return g;
    if (g === "sql" && !ortam.files.some((f) => /\.sql$/i.test(f))) return g;
    if (g === "prisma" && !ortam.files.some((f) => /\.prisma$/i.test(f))) return g;
  }
  return null;
}

/**
 * Builds the content digest of the files behind findings (path → short sha256).
 * Only files that have findings, so the report stays small.
 */
function buildFileDigests(root: string, findings: Finding[]): Record<string, string> {
  const ozetler: Record<string, string> = {};
  for (const b of findings) {
    for (const e of b.evidence) {
      if (e.kind !== "file" || !e.file || ozetler[e.file]) continue;
      try {
        const content = readFileSync(join(root, e.file));
        ozetler[e.file] = createHash("sha256").update(content).digest("hex").slice(0, 16);
      } catch {
        // An unreadable file (deleted, no permission) is not digested — its absence is information.
      }
    }
  }
  return ozetler;
}

export async function scanProject(
  project: Project,
  rules: Rule[],
  options: ScanOptions = {},
): Promise<ProjectReport> {
  const notes: string[] = [];
  const findings: Finding[] = [];
  const rulesRun: string[] = [];
  /** Rules that DID NOT RUN because a precondition was unmet (not a silent "clean"). */
  const gaps: CoverageGap[] = [];
  const root = project.path;

  const runStatic = !options.liveOnly;
  const runLive = !options.staticOnly;
  // Deps (npm audit) needs network access → full scans only, unless told otherwise.
  const runDeps =
    options.includeDeps ?? (!options.liveOnly && !options.staticOnly);

  // --- File collection for the static and deps rules
  let files: string[] = [];
  if (runStatic || runDeps) {
    if (!existsSync(root)) {
      notes.push(`Project path not found: ${root} — static scan skipped.`);
      // Yol yoksa TARAMA HİÇ YAPILMADI. Bunu yalnız bir nota yazmak, raporun
      // "score 0 · ✓ no findings" demesine yol açıyordu: yanlış yapılandırma
      // TEMİZ RAPOR gibi okunuyordu — bir güvenlik aracının verebileceği en
      // kötü cevap. (Gerçek vaka: proje taşındı, targets.json eski yolu
      // gösteriyordu, rapor aylarca yeşil görünebilirdi.)
      // Kesin bir HIGH bulgu üretiyoruz: skor sıfır olamaz, gözden kaçamaz.
      findings.push({
        ruleId: "int-scan-target-missing",
        title: "Audit did not run — the configured project path does not exist",
        owasp: "A09:2021-Security Logging & Monitoring Failures",
        severity: "high",
        confidence: "certain",
        description:
          `targets.json points "${project.name}" at \`${root}\`, but that path does not ` +
          `exist. No file was read, so NO rule could run. This report says nothing about ` +
          `the project's security — it must not be read as "clean".`,
        evidence: [fileEvidence("targets.json", 1, `path: ${root}`)],
        remediation:
          "Point targets.json at the project's current path (or remove the entry if the " +
          "project is gone), then run the scan again.",
      });
    } else {
      files = await collectFiles(root);
      // Yol VAR ama içinde taranacak kaynak dosya YOKSA, sonuç yine "0 bulgu"dur
      // ve yine TEMİZ diye okunur. Gerçek vaka: Sigma-v2 klasöründe yalnız iki
      // log dosyası vardı (kod başka yerde/VPS'te), rapor "score 0" diyordu.
      // Bulunmayan yol kadar tehlikeli, çünkü daha az göze batıyor.
      if (files.length === 0) {
        notes.push(`No scannable source file under ${root} — nothing was measured.`);
        findings.push({
          ruleId: "int-scan-target-empty",
          title: "Audit measured nothing — the project path contains no source file",
          owasp: "A09:2021-Security Logging & Monitoring Failures",
          severity: "high",
          confidence: "certain",
          description:
            `"${project.name}" is registered at \`${root}\` and the path exists, but it ` +
            `contains no scannable source file. Every rule returned nothing because there ` +
            `was nothing to read — this report must not be read as "clean". The code has ` +
            `probably moved, or lives on another machine.`,
          evidence: [fileEvidence("targets.json", 1, `path: ${root}`)],
          remediation:
            "Point targets.json at the directory that actually holds the source (or remove " +
            "the entry). If the code only lives on a server, scan it there.",
        });
      }
    }
  }

  // --- Statik kurallar
  let standards: StandardsResult | undefined;
  if (runStatic && existsSync(root)) {
    const tracked = collectTrackedFiles(root);
    // Two contexts: one is the production surface, one is everything.
    //
    // Test and fixture files are NOT scanned by default. Running a security
    // scanner on itself revealed why: the rule's own search pattern and the
    // fixtures exercising it were reported as CERTAIN CRITICAL findings. Every
    // project that keeps a fake key in its fixtures would get the same false
    // critical — a very common shape.
    const uretimDosyalari = files.filter((f) => !isTestOrFixture(f));
    // ctx and tamCtx read the same (sanitized) content — share one cache so a
    // file is read and parsed once, not twice. rawCtx reads unsanitized text
    // and keeps its own cache.
    const paylasilan: SharedCaches = {
      readCache: new Map<string, string | null>(),
      treeCache: new Map<string, AstFile | null>(),
    };
    const ctx = buildStaticContext(project, root, uretimDosyalari, tracked, true, paylasilan);
    // Rules that compare a list against the directory MUST see the test files.
    const tamCtx = buildStaticContext(project, root, files, tracked, true, paylasilan);
    // Raw contents (comments included) for rules that search for the text itself.
    const rawCtx = buildStaticContext(project, root, uretimDosyalari, tracked, false);
    const ortam = {
      gitDeposu: tracked !== null,
      files: files,
      root: root,
      hasLive: !!project.url && project.owned,
      hasNetwork: await hasNetworkAccess(),
    };
    for (const rule of rules) {
      if (rule.kind !== "static") continue;
      const eksik = unmetRequirement(rule.requires, ortam);
      if (eksik) {
        gaps.push({
          ruleId: rule.id,
          ruleTitle: rule.title,
          requirement: eksik,
          reason: REQUIREMENT_REASON[eksik],
        });
        continue;
      }
      try {
        const ruleCtx = rule.scansComments ? rawCtx : rule.scansTests ? tamCtx : ctx;
        const out = await rule.run(ruleCtx);
        // Confidence: the finding's own, else the rule default, else "likely".
        for (const f of out) {
          if (f.confidence === undefined) {
            f.confidence = rule.confidence ?? "likely";
          }
        }
        findings.push(...out);
        rulesRun.push(rule.id);
      } catch (err) {
        notes.push(
          `Rule ${rule.id} threw: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }

    // --- Standards profile (security + performance checklist)
    if (options.includeStandards ?? true) {
      try {
        standards = await runStandards(ctx);
      } catch (err) {
        notes.push(
          `The standards profile threw: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }
  }

  // --- Dependency rules
  if (runDeps && existsSync(root)) {
    const depsCtx: DepsContext = {
      project,
      root,
      exists: (rel: string) => existsSync(join(root, rel)),
    };
    for (const rule of rules) {
      if (rule.kind !== "deps") continue;
      try {
        const out = await rule.run(depsCtx);
        for (const f of out) {
          if (f.confidence === undefined) f.confidence = rule.confidence ?? "likely";
        }
        findings.push(...out);
        rulesRun.push(rule.id);
      } catch (err) {
        notes.push(
          `Dependency rule ${rule.id} threw: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }
  }

  // --- Live rules (authorisation gate)
  if (runLive) {
    if (!project.owned) {
      notes.push(
        "Live probes skipped: project is owned:false (no authorisation — only owned targets are probed).",
      );
    } else if (!project.url) {
      notes.push("Live probes skipped: no url configured.");
    } else {
      // PREFLIGHT: if a bot/WAF challenge sits in between, no live rule can
      // measure the application — it measures the challenge page and invents
      // findings. In that case the live pass neither says "clean" nor reports
      // anything: it SKIPS. One attempt is not enough — on a full run probing 14
      // projects in sequence, the first request can time out. If the preflight
      // wrongly said "unreachable" and we ran the rules anyway, they would all
      // hit the same wall and invent findings — which is exactly what happened.
      let ctx = buildLiveContext(project);
      let on = await ctx.probe("/");
      if (!on.ok) on = await ctx.probe("/");
      // If the base URL redirects within the same host (http→https), use the
      // target: otherwise every rule measures the redirect response.
      const target = redirectTarget(project.url, on);
      if (target) {
        notes.push(
          `Live base URL ${project.url} redirects to ${target} (HTTP ${on.status}); ` +
            `the measurement used the target URL. Updating targets.json to ${target} ` +
            `removes one round trip up front.`,
        );
        ctx = buildLiveContext({ ...project, url: target });
        on = await ctx.probe("/");
      }
      // FAIL-CLOSED: if the preflight gets no answer, no live rule will either.
      // Knowing you could not measure beats believing you did.
      const engel = on.ok
        ? challengeMi(on.status, on.headers, on.bodySnippet ?? "")
        : `the preflight check got no answer (${on.error ?? "unreachable"})`;
      if (engel) {
        notes.push(
          on.ok
            ? `Live probes SKIPPED: ${engel} sits in front of the app (HTTP ${on.status}). ` +
              `What would be measured is a challenge page, not the app — no findings produced. ` +
              `To measure it, open the protection with a bypass token (Vercel: Protection Bypass for Automation) or allowlist the IP.`
            : `Live probes SKIPPED: ${engel}. Both attempts went unanswered — ` +
              `the site may be down, the URL wrong, or the network blocked. No findings produced: ` +
              `what cannot be measured is neither "clean" nor "vulnerable".`,
        );
      } else {
        // THE PREFLIGHT ALONE IS NOT ENOUGH. A Vercel challenge occasionally lets
        // `/` through (of two consecutive full runs, one produced 28 false
        // findings and the other was clean). So we keep watch throughout the run:
        // if ANY probe sees a challenge, ALL live findings for that project are
        // discarded. A half-measured pass is more dangerous than an unmeasured one.
        let turEngeli: string | null = null;
        const watchdogCtx: LiveContext = {
          ...ctx,
          probe: async (path, init) => {
            const result = await ctx.probe(path, init);
            if (!turEngeli && result.ok) {
              turEngeli = challengeMi(result.status, result.headers, result.bodySnippet ?? "");
            }
            return result;
          },
        };
        const liveFindings: Finding[] = [];
        for (const rule of rules) {
        if (rule.kind !== "live") continue;
        try {
          const out = await rule.run(watchdogCtx);
          for (const f of out) {
            if (f.confidence === undefined) f.confidence = rule.confidence ?? "likely";
          }
          liveFindings.push(...out);
          rulesRun.push(rule.id);
        } catch (err) {
          notes.push(
            `Live rule ${rule.id} threw: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
        }
        if (turEngeli) {
          notes.push(
            `Live probes ABORTED: ${turEngeli} kicked in mid-run — ` +
              `${liveFindings.length} live finding(s) discarded (they would have measured a challenge page). ` +
              `The preflight passed; the protection applies to only some requests.`,
          );
        } else {
          findings.push(...liveFindings);
        }
      }
    }
  }

  const counts = tallyCounts(findings);
  const { certain, heuristic } = tallyByConfidence(findings);
  return {
    project,
    findings,
    counts,
    certainCounts: certain,
    heuristicCounts: heuristic,
    score: riskScore(counts),
    /** PİSLİK SKORU — karşılaştırılabilir 0-100 kirlilik (alt sınırı; bkz. severity.ts). */
    pislik: pislikSkoru(counts, gaps.length),
    rulesRun,
    notes,
    standards,
    coverage: existsSync(root) ? measureCoverage(root) : undefined,
    gaps,
    fileDigests: buildFileDigests(root, findings),
  };
}

export function hasCritical(reports: ProjectReport[]): boolean {
  return reports.some((r) => r.counts.critical > 0);
}

export { relative };
