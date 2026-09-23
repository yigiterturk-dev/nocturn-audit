import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { DepsRule } from "../core/rule.js";

const execFileAsync = promisify(execFile);

/**
 * A06 — outdated or deprecated dependencies.
 *
 * `a06-npm-audit` covers real CVEs; this rule COMPLEMENTS it (they do not
 * overlap): it flags packages several MAJOR versions behind (heuristic → likely)
 * and known deprecated packages. Since this is a maintenance and operations
 * signal rather than a vulnerability, confidence stays "likely" and severity low.
 */

/** Extract deps + devDeps from package.json (under the root). */
function readDeps(root: string): {
  deps: Record<string, string>;
  raw: string | null;
} {
  try {
    const raw = readFileSync(join(root, "package.json"), "utf8");
    const pkg = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return {
      deps: { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) },
      raw,
    };
  } catch {
    return { deps: {}, raw: null };
  }
}

/** Pull the first major integer out of a version string (^, ~, >= etc. are stripped). */
function majorOf(v: string | undefined): number | null {
  if (!v) return null;
  const m = /(\d+)\./.exec(v) ?? /^\D*(\d+)\s*$/.exec(v);
  if (!m) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

/**
 * Known deprecated or unmaintained packages (an offline heuristic).
 * Only common, clear-cut cases — kept narrow to avoid an FP flood.
 */
const KNOWN_DEPRECATED: Record<string, string> = {
  request: "No longer maintained (deprecated). Use got, undici or native fetch.",
  "node-sass": "Deprecated — LibSass is dead. Move to the `sass` (Dart Sass) package.",
  tslint: "Deprecated — move to ESLint with typescript-eslint.",
  "@babel/polyfill": "Deprecated — use core-js and regenerator-runtime directly.",
  "left-pad": "Unnecessary micro-package — use String.prototype.padStart.",
  "istanbul": "Deprecated — use nyc or c8.",
  "gulp-util": "Deprecated — use the individual small modules directly.",
  "core-js@2": "core-js 2 is unmaintained — move to core-js 3.",
  "har-validator": "Deprecated dependency.",
  "uuid@3": "uuid 3 is outdated — move to uuid 9 or later.",
  "querystring": "Node's built-in 'querystring' is deprecated — use URLSearchParams.",
  "moment": "In maintenance mode — prefer day.js, date-fns or Temporal.",
  "@vercel/node-bridge": "Deprecated internal Vercel package.",
};

export interface OutdatedEntry {
  current?: string;
  wanted?: string;
  latest?: string;
}

/**
 * Evaluates `npm outdated --json` output: returns packages >= 2 majors behind.
 * Pure (no network) → exported for unit testing.
 */
export function evaluateOutdated(
  parsed: Record<string, OutdatedEntry | OutdatedEntry[]>,
  deps: Record<string, string>,
): Array<{ pkg: string; behind: number; curMajor: number; latestMajor: number; entry: OutdatedEntry }> {
  const out: Array<{ pkg: string; behind: number; curMajor: number; latestMajor: number; entry: OutdatedEntry }> = [];
  for (const [pkg, val] of Object.entries(parsed)) {
    const entry = Array.isArray(val) ? val[0] : val;
    if (!entry) continue;
    const curMajor = majorOf(entry.current) ?? majorOf(deps[pkg]);
    const latestMajor = majorOf(entry.latest);
    if (curMajor == null || latestMajor == null) continue;
    const behind = latestMajor - curMajor;
    if (behind < 2) continue;
    out.push({ pkg, behind, curMajor, latestMajor, entry });
  }
  return out;
}

/** Returns the known deprecated packages among the deps in package.json. */
export function findDeprecated(
  deps: Record<string, string>,
): Array<{ name: string; note: string; version: string }> {
  const out: Array<{ name: string; note: string; version: string }> = [];
  for (const name of Object.keys(deps)) {
    const note = KNOWN_DEPRECATED[name];
    if (note) out.push({ name, note, version: deps[name] });
  }
  return out;
}

export const outdatedDeps: DepsRule = {
  id: "a06-outdated-deps",
  title: "Outdated or deprecated dependencies",
  owasp: "A06:2021-Vulnerable & Outdated Components",
  severity: "medium",
  kind: "deps",
  // Dependency scanning: the manifest and registry access are both required.
  requires: ["npm", "net"],
  confidence: "likely",
  async run(ctx): Promise<Finding[]> {
    if (!ctx.exists("package.json")) return [];
    const findings: Finding[] = [];
    const { deps } = readDeps(ctx.root);

    // --- 1) Known deprecated packages (offline) ---
    for (const d of findDeprecated(deps)) {
      findings.push({
        ruleId: this.id,
        title: `Deprecated or unmaintained package: ${d.name}`,
        owasp: this.owasp,
        severity: "low",
        confidence: "likely",
        cwe: "CWE-1104",
        description: `${d.name} is deprecated or unmaintained. ${d.note}`,
        evidence: [fileEvidence("package.json", 1, `${d.name}: ${d.version}`)],
        remediation: d.note,
      });
    }

    // --- 2) Packages N majors behind (npm outdated --json) ---
    // Without node_modules, `npm outdated` is not meaningful (and it tries to
    // reach the registry) → skip. Run it only on installed projects.
    if (!ctx.exists("node_modules")) return findings;
    let stdout = "";
    try {
      const res = await execFileAsync("npm", ["outdated", "--json"], {
        cwd: ctx.root,
        maxBuffer: 20 * 1024 * 1024,
        timeout: 120_000,
      });
      stdout = res.stdout;
    } catch (err: unknown) {
      // npm outdated exits non-zero when it finds an outdated package, but
      // stdout yine JSON'dur.
      const e = err as { stdout?: string };
      if (e.stdout) stdout = e.stdout;
      else return findings; // no network / could not run → return only the deprecated findings
    }

    if (!stdout.trim()) return findings;
    let parsed: Record<string, OutdatedEntry | OutdatedEntry[]>;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return findings;
    }

    for (const o of evaluateOutdated(parsed, deps)) {
      findings.push({
        ruleId: this.id,
        title: `Dependency is ${o.behind} major version(s) behind: ${o.pkg}`,
        owasp: this.owasp,
        severity: "medium",
        confidence: "likely",
        cwe: "CWE-1104",
        description: `${o.pkg} is installed at major ${o.curMajor} while the latest is ${o.latestMajor} (${o.behind} major(s) behind). Old majors may stop receiving security patches, and the upgrade gets harder as breaking changes pile up.`,
        evidence: [
          fileEvidence(
            "package.json",
            1,
            `${o.pkg}: kurulu ${o.entry.current ?? deps[o.pkg] ?? "?"} → latest ${o.entry.latest}`,
          ),
        ],
        remediation: `Upgrade ${o.pkg} one major at a time, reading the changelog for breaking changes. Confirm the state with \`npm outdated ${o.pkg}\`.`,
      });
    }

    return findings;
  },
};
