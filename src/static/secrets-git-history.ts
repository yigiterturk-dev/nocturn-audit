import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

const execFileAsync = promisify(execFile);

/**
 * A02 — secrets embedded in git history.
 *
 * Scans the ADDED lines of `git log -p` output: known provider key patterns,
 * high-entropy literal assignments, and committed real `.env` files.
 * A secret survives in history even after the working file is cleaned — hence a separate rule.
 */

interface Pattern {
  name: string;
  re: RegExp;
  severity: Severity;
}

const PROVIDER_PATTERNS: Pattern[] = [
  { name: "Stripe secret key", re: /sk_(live|test)_[A-Za-z0-9]{16,}/, severity: "critical" },
  { name: "Stripe restricted key", re: /rk_(live|test)_[A-Za-z0-9]{16,}/, severity: "high" },
  { name: "AWS access key", re: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "Google API key", re: /AIza[0-9A-Za-z_\-]{35}/, severity: "high" },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{36,}/, severity: "critical" },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/, severity: "high" },
  { name: "OpenAI key", re: /sk-(proj-)?[A-Za-z0-9]{20,}/, severity: "critical" },
  { name: "JWT/service token", re: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/, severity: "high" },
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, severity: "critical" },
];

// A CONSTANT STRING LITERAL assigned to a sensitively named variable (quotes REQUIRED).
// Because quotes are required, expression/call/identifier right-hand sides such as
// `= decrypt(x)`, `= authHeader.slice(7)`, `= data.token`, `= process.env.X` and
// `= req.headers.get(...)` DO NOT match — only genuinely embedded literals do.
const SECRET_ASSIGN =
  /\b(secret|api[_-]?key|apikey|password|passwd|token|private[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*["'`]([^"'`\n]{18,})["'`]/i;

const PLACEHOLDER =
  /(process\.env|import\.meta\.env|your[_-]?|xxx|placeholder|example|changeme|dummy|<[^>]+>|\$\{)/i;

// Real key prefixes (provider formats + JWT + PEM).
const KEY_PREFIX = /^(sk[-_]|rk_|AKIA|AIza|gh[pousr]_|xox[baprs][-_]|eyJ|-----BEGIN)/;

/**
 * Whether a string literal has the shape of a REAL key or password.
 * Only: a provider prefix | JWT | PEM | a long opaque token or password (key
 * character set + high entropy + a digit OR mixed case). That last condition
 * rules out dictionary-like dummies such as `meta-app-secret-very-hidden`
 * (all lowercase, no digits).
 */
function looksLikeRealKey(value: string): boolean {
  if (KEY_PREFIX.test(value)) return true;
  if (value.length < 18) return false;
  // Natural language / spaces / a sentence → not a real secret.
  if (!/^[A-Za-z0-9._~+/=-]+$/.test(value)) return false;
  const hasDigit = /[0-9]/.test(value);
  const mixedCase = /[a-z]/.test(value) && /[A-Z]/.test(value);
  if (!hasDigit && !mixedCase) return false;
  return shannon(value) >= 3.6;
}

// A real .env (excluding .example/.sample/.template)
const REAL_ENV_FILE = /(^|\/)\.env(\.[A-Za-z0-9_]+)?$/;
const ENV_EXAMPLE = /\.(example|sample|template|dist)$/;

// Files excluded from the "secret embedded in code" angle:
//  - test/fixture/mock files (dummy fixture secrets)
//  - documentation (.md/.mdx/.txt/.rst — not code)
//  - lock files (pnpm-lock/package-lock/yarn.lock, *-lock.*)
const TEST_FILE =
  /(^|\/)(__tests__|__mocks__)\/|(^|\/)(fixtures?|mocks?)\/|\.(test|spec)\.[cm]?[jt]sx?$/i;
const DOC_FILE = /\.(md|mdx|txt|rst)$/i;
const LOCK_FILE =
  /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?)$|-lock\.[a-z0-9]+$/i;

/** Is the file excluded from the code-embedded secret scan (test/doc/lock)? */
function isExcludedFile(file: string): boolean {
  const f = file.replace(/\\/g, "/");
  return TEST_FILE.test(f) || DOC_FILE.test(f) || LOCK_FILE.test(f);
}

// Google/Firebase CLIENT key config files — the AIza... keys there are CLIENT
// keys, designed to be embedded in an APK or bundle (not secrets).
const CLIENT_GOOGLE_CONFIG = /google-services\.json|GoogleService-Info\.plist/i;

/**
 * Decodes the payload.role field of a Supabase/JWT token.
 * SECURITY: the token and the full payload are NEVER returned or logged — only
 * `role` is read, and it is redacted. `anon` = public publishable key, `service_role` = secret.
 * Returns null when it cannot be decoded.
 */
function jwtRole(token: string): string | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    let b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const json = Buffer.from(b64, "base64").toString("utf8");
    const obj = JSON.parse(json) as { role?: unknown };
    // Read ONLY the role field; no other credential material is touched.
    return typeof obj.role === "string" ? obj.role : null;
  } catch {
    return null;
  }
}

function shannon(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let h = 0;
  for (const c in freq) {
    const p = freq[c] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export interface GitSecretHit {
  file: string;
  commit: string;
  name: string;
  severity: Severity;
  snippet: string;
}

/**
 * `git log -p` (veya benzeri unified diff) metnini tarar. Saf fonksiyon — test edilebilir.
 */
export function scanGitDiff(diff: string): GitSecretHit[] {
  const hits: GitSecretHit[] = [];
  const seen = new Set<string>();
  let commit = "";
  let file = "";
  const committedEnv = new Set<string>();

  for (const line of diff.split(/\r?\n/)) {
    const cm = /^commit\s+([0-9a-f]{7,40})/i.exec(line);
    if (cm) {
      commit = cm[1].slice(0, 10);
      continue;
    }
    const fm = /^\+\+\+ b\/(.+)$/.exec(line);
    if (fm) {
      file = fm[1].trim();
      // has a real .env been committed?
      if (REAL_ENV_FILE.test(file) && !ENV_EXAMPLE.test(file)) {
        const key = `env:${file}`;
        if (!committedEnv.has(key)) {
          committedEnv.add(key);
          hits.push({
            file,
            commit,
            name: "Committed .env file",
            severity: "high",
            snippet: `${file} was added to git history (.env was committed)`,
          });
        }
      }
      continue;
    }
    // added lines only (start with +, not +++)
    if (!line.startsWith("+") || line.startsWith("+++")) continue;
    // Test/doc/lock files are not "code-embedded secrets" → skip (the committed
    // .env distinction is made separately above and is unaffected).
    if (file && isExcludedFile(file)) continue;
    const added = line.slice(1);

    for (const p of PROVIDER_PATTERNS) {
      const m = p.re.exec(added);
      if (m) {
        // JWT/service token: decode the role. role:"anon" → public publishable
        // key, NOT a secret, skip. Only service_role (or undecodable) is a real secret.
        if (p.name === "JWT/service token") {
          const role = jwtRole(m[0]);
          if (role === "anon") continue;
        }
        // An AIza Google/Firebase key in a client config file → client key, skip.
        // (A real service account, which contains private_key/client_email, is
        //  still caught by the "Private key block" pattern.)
        if (p.name === "Google API key" && CLIENT_GOOGLE_CONFIG.test(file)) {
          continue;
        }
        const key = `${commit}:${file}:${p.name}:${m[0].slice(0, 8)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        hits.push({
          file: file || "(bilinmeyen)",
          commit,
          name: p.name,
          // A FAKE KEY IN A FIXTURE IS NOT A LEAK — but going completely silent
          // is wrong too: a REAL key pasted into a fixture path by accident sits
          // in exactly the same place. So we do not mute it; we lower the
          // severity and say what to do.
          //
          // The tool's own canary (a deliberately planted fake Stripe key) was
          // reported as CERTAIN CRITICAL in its own git history. When the first
          // critical finding an audit tool shows you is its own test data, the
          // team's trust in it dies on day one.
          severity: fixturePath(file) ? "low" : p.severity,
          snippet: added.replace(p.re, (x) => x.slice(0, 6) + "…redacted").trim().slice(0, 200),
        });
      }
    }

    const sm = SECRET_ASSIGN.exec(added);
    if (sm && !PLACEHOLDER.test(added)) {
      const value = sm[2];
      // It must have the SHAPE of a real key or password (provider prefix | JWT |
      // PEM | long opaque high-entropy token). Hashes, UUIDs, ids and dictionary dummies are filtered out.
      if (looksLikeRealKey(value)) {
        const key = `${commit}:${file}:entropy:${value.slice(0, 8)}`;
        if (!seen.has(key)) {
          seen.add(key);
          hits.push({
            file: file || "(bilinmeyen)",
            commit,
            name: "High-entropy literal secret",
            severity: "high",
            snippet: added.replace(value, value.slice(0, 4) + "…redacted").trim().slice(0, 200),
          });
        }
      }
    }
  }
  return hits;
}


/**
 * Is this a test or fixture path? (where fake keys legitimately live)
 */
export function fixturePath(file: string): boolean {
  const f = (file || "").replace(/\\/g, "/");
  return /(^|\/)(test|tests|__tests__|spec|fixtures?|canary|mocks?|examples?)\//.test(f) ||
    /\.(test|spec)\.[cm]?[jt]sx?$/.test(f);
}

export const secretsGitHistory: StaticRule = {
  id: "a02-secrets-git-history",
  title: "Secret embedded in git history",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  cwe: "CWE-540",
  kind: "static",
  // Without git history and tracking information this rule can measure NOTHING.
  // Returning `[]` outside a repository would read as "clean" — but nothing was looked at.
  requires: ["git"],
  // A secret actually present in git history → deterministic.
  confidence: "certain",
  async run(ctx: StaticContext): Promise<Finding[]> {
    // Silently skip when this is not a git repository.
    try {
      await execFileAsync("git", ["rev-parse", "--is-inside-work-tree"], {
        cwd: ctx.root,
        timeout: 10_000,
      });
    } catch {
      return [];
    }

    let stdout = "";
    try {
      const res = await execFileAsync(
        "git",
        ["log", "-p", "--all", "--no-color", "-n", "500"],
        { cwd: ctx.root, maxBuffer: 48 * 1024 * 1024, timeout: 120_000 },
      );
      stdout = res.stdout;
    } catch (err: unknown) {
      const e = err as { stdout?: string };
      if (e.stdout) stdout = e.stdout;
      else return [];
    }

    const hits = scanGitDiff(stdout);
    return hits.map((h) => ({
      ruleId: this.id,
      title: `${this.title} — ${h.name}`,
      owasp: this.owasp,
      severity: h.severity,
      cwe: this.cwe,
      description:
        `${h.name} was found in git history (commit ${h.commit || "?"}). Even if the file was later deleted or cleaned, the secret remains in history and anyone who clones the repository can read it.` +
        (fixturePath(h.file)
          ? " NOTE: this is a TEST or FIXTURE path, most likely a deliberately fake key, so the severity was lowered. Still worth a look: a REAL key pasted into a fixture by accident would sit in exactly the same place."
          : ""),
      evidence: [fileEvidence(h.file, 1, `[commit ${h.commit || "?"}] ${h.snippet}`)],
      remediation:
        "Revoke and reissue the leaked key at the provider immediately. Purge it from history with git filter-repo or BFG, force-push, and add .env to .gitignore.",
      remediationCode:
        "git rm --cached .env && echo '.env' >> .gitignore\n" +
        "# Purge from history (warning: this rewrites history):\n" +
        "git filter-repo --path .env --invert-paths",
    }));
  },
};
