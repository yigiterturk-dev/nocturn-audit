import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — a .env file is in the repository or missing from .gitignore.
 * .env files containing real secrets must never enter git.
 */

export const envCommitted: StaticRule = {
  id: "a02-env-file-committed",
  title: ".env file committed to git",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  kind: "static",
  // Without git history and tracking information this rule can measure NOTHING.
  // Returning `[]` outside a repository would read as "clean" — but nothing was looked at.
  requires: ["git"],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const gitignore = ctx.read(".gitignore") ?? "";
    const ignoresEnv =
      /^\s*\.env(\*|\.local|\.\*)?\s*$/m.test(gitignore) ||
      /^\s*\*?\.env\*?\s*$/m.test(gitignore) ||
      /(^|\n)\s*\.env(\b|\*)/.test(gitignore);

    const envFiles = ctx.files.filter((f) => {
      const base = f.replace(/\\/g, "/").split("/").pop() ?? "";
      return /^\.env/.test(base) && !/\.example|\.sample|\.template/.test(base);
    });

    // .env files with real secrets (example/sample/template are already filtered out)
    for (const file of envFiles) {
      const base = (file.replace(/\\/g, "/").split("/").pop() ?? "");
      const content = ctx.read(file) ?? "";
      const hasRealValue = /^[A-Z0-9_]+\s*=\s*[^\s#][^\n]{6,}/m.test(content);
      if (!hasRealValue) continue;

      const tracked = ctx.isTracked(file);
      if (tracked) {
        // A REAL leak: the file is tracked by git → it entered the repository.
        findings.push({
          ruleId: this.id,
          title: `${base} has been committed to git`,
          owasp: this.owasp,
          severity: "high",
          confidence: "certain",
          description: `${base} contains real-looking values and is tracked by git. Anyone who clones the repository gets these secrets — this is an outright leak.`,
          evidence: [fileEvidence(file, 1, "(.env contents redacted)")],
          remediation:
            "Untrack the file (git rm --cached), add `.env*` to .gitignore, purge it from history (git filter-repo or BFG), and revoke and reissue every exposed secret.",
        });
      } else if (ctx.isGitRepo) {
        // The file exists on disk but git does not track it (gitignored): the RIGHT
        // place for secrets. Not an in-code or committed leak → an informational low note only.
        findings.push({
          ruleId: this.id,
          title: `${base} yerelde mevcut (git izlemiyor)`,
          owasp: this.owasp,
          severity: "info",
          confidence: "certain",
          description: `${base} exists in the working tree but is not tracked by git (it is gitignored). This is the expected, correct way to hold environment secrets — not a leak. Just never commit it.`,
          evidence: [fileEvidence(file, 1, "(gitignored .env — no leak)")],
          remediation:
            "No action needed. Just keep the file covered by `.gitignore`.",
        });
      }
      // Not a git repository: no tracking information → skip quietly (do not produce an FP).
    }

    // With no .gitignore at all, or no .env pattern, a forward-looking low warning
    if (!ignoresEnv && ctx.exists("package.json")) {
      findings.push({
        ruleId: this.id,
        title: ".gitignore has no .env pattern",
        owasp: this.owasp,
        severity: "low",
        confidence: "likely",
        description:
          ".gitignore contains no rule for .env*. Add one so a secret cannot be committed by accident.",
        evidence: [fileEvidence(".gitignore", 1, gitignore ? "(no .env pattern)" : "(no .gitignore)")],
        remediation: "Add `.env*` (and `!.env.example`) to .gitignore.",
      });
    }

    return findings;
  },
};
