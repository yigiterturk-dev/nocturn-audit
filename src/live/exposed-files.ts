import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

/**
 * A05 (live) — exposed sensitive files: .env, .git, source maps.
 * Non-destructive: GET only; it does not download content, it checks a signature.
 */

interface Target {
  path: string;
  severity: Severity;
  /** the signature confirming the response really is that file */
  signature: RegExp;
  title: string;
  fix: string;
}

const TARGETS: Target[] = [
  {
    path: "/.env",
    severity: "critical",
    signature: /^[A-Z0-9_]+\s*=/m,
    title: "Publicly reachable .env file",
    fix: "Stop serving .env publicly, fix the hosting rewrite/ignore rules, and revoke every leaked secret.",
  },
  {
    path: "/.git/config",
    severity: "high",
    signature: /\[core\]|repositoryformatversion/i,
    title: "Publicly reachable .git directory",
    fix: "Remove the .git directory from the web root or block access to it.",
  },
  {
    path: "/.git/HEAD",
    severity: "high",
    signature: /ref:\s*refs\//,
    title: "Publicly reachable .git/HEAD",
    fix: "Block access to .git.",
  },
];

export const liveExposedFiles: LiveRule = {
  id: "a05-live-exposed-files",
  title: "Live: sensitive files exposed on the web",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "high",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const t of TARGETS) {
      const res = await ctx.probe(t.path);
      if (!res.ok) continue;
      if (res.status !== 200) continue;
      // Filter out the SPA fallback (which returns index.html): skip when HTML came back with no signature
      if (!t.signature.test(res.bodySnippet)) continue;
      findings.push({
        ruleId: this.id,
        title: t.title,
        owasp: this.owasp,
        severity: t.severity,
        description: `${t.path} returned 200 and its content matched the real file signature. A sensitive file is exposed to the internet.`,
        evidence: [
          httpEvidence(
            res.requestLine,
            `HTTP ${res.status}\n${res.bodySnippet.slice(0, 200)}`,
          ),
        ],
        remediation: t.fix,
      });
    }
    return findings;
  },
};
