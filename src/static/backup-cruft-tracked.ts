import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A05 — backup and leftover files are tracked by git, or fall outside
 * .gitignore.
 *
 * `*.yedek`, `*.bak`, `*.old`, `venv.eski/`, `*.db.yedek` gibi elle
 * copies taken by hand, or old environments:
 *   - if tracked (git ls-files) they bloat the repository and, because they hold
 *     OLD CODE, they are a confusion and security risk (stale, unpatched copies),
 *   - if not covered by .gitignore, a single `git add -A` commits them silently.
 *     commit edebilir.
 *
 * Real case: a server working tree held 134 MB of untracked leftovers (an old
 * venv, *.bak files, a database backup) that .gitignore did not cover; one
 * `git add -A` could have pushed all of it into the repository.
 */

const CRUFT_NAME =
  /(\.yedek(-[\w.]+)?$|\.bak$|\.old$|\.orig$|~$|\.eski([\w.-]*)?\/|\.oncesi-|-oncesi\.|copy\s*\d*\.|\bkopya\b|\.db\.yedek)/i;

const CRUFT_DIR = /(^|\/)(venv\.eski|env\.eski|node_modules\.eski|\.eski|backup|yedekler?)(\/|$)/i;

export const backupCruftTracked: StaticRule = {
  id: "a05-backup-cruft-tracked",
  title: "Backup and leftover files are tracked or not gitignored",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "low",
  kind: "static",
  // Without git history and tracking information this rule can measure NOTHING.
  // Returning `[]` outside a repository would read as "clean" — but nothing was looked at.
  requires: ["git"],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // Does .gitignore cover these patterns?
    const gi = ctx.read(".gitignore") ?? "";
    const ignoresCruft = /(\*\.yedek|\*\.bak|\.eski|\*\.old|\*~)/i.test(gi);

    const kalintilar: string[] = [];
    for (const file of ctx.files) {
      const f = file.replace(/\\/g, "/");
      if (CRUFT_NAME.test(f) || CRUFT_DIR.test(f)) kalintilar.push(f);
    }

    // And are there tracked leftovers — the highest risk.
    const tracked = kalintilar.filter((f) => ctx.isTracked?.(f));

    if (kalintilar.length === 0 && ignoresCruft) return findings;

    if (tracked.length > 0) {
      findings.push({
        ruleId: this.id,
        title: "Backup and leftover files are TRACKED by git",
        owasp: this.owasp,
        severity: "medium",
        description:
          `${tracked.length} backup/leftover file(s) are tracked by git ` +
          `(e.g. ${tracked.slice(0, 3).join(", ")}). Stale copies of code bloat the ` +
          `repository, and unpatched versions cause confusion and carry security risk.`,
        evidence: [fileEvidence(tracked[0], 1, tracked[0])],
        remediation:
          "Untrack the leftovers with `git rm --cached`, delete them, and " +
          ".gitignore'a desen ekleyin (*.yedek, *.bak, *.eski, venv.eski*/).",
      });
    } else if (kalintilar.length > 0 && !ignoresCruft) {
      findings.push({
        ruleId: this.id,
        title: "Backup and leftover files are not covered by .gitignore",
        owasp: this.owasp,
        severity: "low",
        description:
          `There are ${kalintilar.length} backup/leftover file(s) (e.g. ` +
          `${kalintilar.slice(0, 3).join(", ")}) that .gitignore does not ` +
          `cover. A single `+"`git add -A`"+` can commit them all silently.`,
        evidence: [fileEvidence(kalintilar[0], 1, kalintilar[0])],
        remediation:
          "Add these patterns to .gitignore: *.bak, *.old, *.orig, *.backup, " +
          "*-copy.*, venv.old*/. Then delete the leftovers you do not need.",
      });
    }
    return findings;
  },
};
