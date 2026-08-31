import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — a secret, API key or token hardcoded in source.
 * Known provider patterns plus high-entropy assignment detection.
 */

interface Pattern {
  name: string;
  re: RegExp;
  severity: "critical" | "high";
}

const PROVIDER_PATTERNS: Pattern[] = [
  { name: "Stripe secret key", re: /sk_(live|test)_[A-Za-z0-9]{16,}/, severity: "critical" },
  { name: "Stripe restricted key", re: /rk_(live|test)_[A-Za-z0-9]{16,}/, severity: "high" },
  { name: "AWS access key", re: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "Google API key", re: /AIza[0-9A-Za-z_\-]{35}/, severity: "high" },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{36,}/, severity: "critical" },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/, severity: "high" },
  { name: "OpenAI key", re: /sk-(proj-)?[A-Za-z0-9]{20,}/, severity: "critical" },
  { name: "Supabase/JWT (service) token", re: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/, severity: "high" },
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, severity: "critical" },
  { name: "iyzico key", re: /(iyzico|IYZICO)[^\n]{0,20}(sandbox|api)[-_]?key['"\s:=]+[A-Za-z0-9]{16,}/i, severity: "high" },
];

// A key = "value" assignment; a sensitive key name with a long constant string value
const SECRET_ASSIGN =
  /\b(secret|api[_-]?key|apikey|password|passwd|token|private[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i;

const PLACEHOLDER =
  /(process\.env|import\.meta\.env|your[_-]?|xxx|placeholder|example|changeme|<[^>]+>|\$\{)/i;

const shannon = (s: string): number => {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let h = 0;
  for (const c in freq) {
    const p = freq[c] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
};

// A real env file (.env, .env.local, .env.production …) — excluding .example/.sample/.template.
const ENV_FILE = /(^|\/)\.env(\.[\w.-]+)?$/;
const ENV_EXAMPLE = /\.(example|sample|template|dist)$/;

const isEnvFile = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return ENV_FILE.test(f) && !ENV_EXAMPLE.test(f);
};

const skipFile = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /\.env(\.example|\.sample|\.template)$/.test(f) ||
    /(test|spec|__tests__|fixtures?)/.test(f) ||
    /\.lock$|package-lock/.test(f) ||
    // Scraped third-party HTML dumps and raw fixtures → not the project's own
    // secret (e.g. another site's public browser key).
    /\.html?$/i.test(f) ||
    /(^|\/)(scraped|samples?)\//i.test(f) ||
    /_raw\.[a-z0-9]+$/i.test(f)
  );
};

// Is this an UPPER_SNAKE_CASE env-var NAME (rather than its value)? E.g. "AGGREGATOR_WEBHOOK_SECRET".
// Even assigned as a string that is NOT a real secret — it is used as a key inside env(...).
const isEnvVarName = (value: string): boolean =>
  /^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$/.test(value);

export const hardcodedSecrets: StaticRule = {
  id: "a02-hardcoded-secret",
  title: "Secret or API key hardcoded in source",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "critical",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  // A constant secret in source, or in a file committed to git → a deterministic finding.
  confidence: "certain",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (skipFile(file)) continue;
      // `.env*` files are the RIGHT place for secrets. It is a leak only when the
      // file is actually tracked by git (committed); a gitignored `.env.local` is
      // NOT a hardcoded secret (see the a02-env-file-committed rule).
      if (isEnvFile(file) && !ctx.isTracked(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];

        // 1) provider patterns
        for (const p of PROVIDER_PATTERNS) {
          if (p.re.test(raw)) {
            const key = `${file}:${i}:${p.name}`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({
              ruleId: this.id,
              title: `${this.title} — ${p.name}`,
              owasp: this.owasp,
              severity: p.severity,
              description: `A literal secret matching the ${p.name} pattern was found in source. Keys that enter the repository are a leak and unauthorised-access risk.`,
              evidence: [fileEvidence(file, i + 1, raw.replace(p.re, (m) => m.slice(0, 6) + "…redacted"))],
              remediation:
                "Remove the key from the code, move it to an environment variable or secret manager, and revoke and reissue the leaked key at the provider immediately.",
            });
          }
        }

        // 2) high-entropy assignment
        const m = SECRET_ASSIGN.exec(raw);
        if (m) {
          const value = m[2];
          if (PLACEHOLDER.test(raw) || PLACEHOLDER.test(value)) continue;
          // If the value is an env-var NAME (UPPER_SNAKE_CASE, e.g. AGGREGATOR_WEBHOOK_SECRET)
          // it is a config key rather than a secret value → skip.
          if (isEnvVarName(value)) continue;
          if (value.length >= 16 && shannon(value) >= 3.5) {
            const key = `${file}:${i}:entropy`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({
              ruleId: this.id,
              title: `${this.title} — high-entropy literal`,
              owasp: this.owasp,
              severity: "high",
              description:
                "A high-entropy literal is assigned to a sensitively named variable (secret/token/password/api_key). This is probably a real secret.",
              evidence: [fileEvidence(file, i + 1, raw.replace(value, value.slice(0, 4) + "…redacted"))],
              remediation:
                "Move the value to an environment variable, delete the literal, and rotate it if it is a real secret.",
            });
          }
        }
      }
    }
    return findings;
  },
};
