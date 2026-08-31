import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A09 — backups are taken but their restorability is never tested.
 *
 * An untested backup is not a backup, it is a hope. A corrupt dump is only
 * discovered to be corrupt on the day you need it — which is the one day nothing
 * can be tested.
 */
const YEDEK_BETIGI = /(backup|yedek|dump|snapshot)/i;
const DOKUM = /(pg_dump|mysqldump|sqlite3?\s+\.dump|mongodump|\bdump\b)/i;
const REHEARSAL = /(pg_restore|psql[\s\S]{0,80}-f|mysql\s+<|restore|geri yükle|prova|rehearsal|verify)/i;

/**
 * A BACKUP IS SOMETHING WRITTEN SOMEWHERE.
 *
 * This rule once reported a `scripts/dump-schema.mjs` as "backup taken but no
 * rehearsal". That script prints the schema TO THE SCREEN — it is an inspection
 * tool, not a backup system. Asking about the "restorability" of a dump whose
 * output is never stored is meaningless.
 *
 * The distinguishing signal: does the output go somewhere DURABLE? Writing to a
 * file, piping to a stream, uploading to object storage, redirecting in a shell.
 * If not, this is not a backup and the rule should stay quiet.
 */
const KALICI_CIKTI =
  /(writeFileSync|createWriteStream|fs\.write|writeFile|appendFile|\.pipe\s*\(|upload|putObject|uploadObject|copyTo|s3|storage\.from|createGzip|gzipSync|>\s*["'`$\w./]|>>\s*["'`$\w./]|tee\s)/i;

export const backupWithoutRestoreRehearsal: StaticRule = {
  id: "int-backup-without-restore-rehearsal",
  title: "Backups are taken but never restore-rehearsed",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.(ts|js|mjs|sh)$/.test(file)) continue;
      if (!YEDEK_BETIGI.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      // If the output is written nowhere, this is an inspection tool, not a backup.
      if (!KALICI_CIKTI.test(content)) continue;
      if (!content || !DOKUM.test(content)) continue;
      if (REHEARSAL.test(content)) continue;

      findings.push({
        ruleId: "int-backup-without-restore-rehearsal",
        title: "Backups are taken but never restore-rehearsed",
        owasp: "A09:2021-Security Logging & Monitoring Failures",
        severity: "high",
        confidence: "likely",
        description:
          `\`${file}\` takes a dump but never restores it anywhere. ` +
          "The only way to know a dump is valid is to restore it.",
        evidence: [fileEvidence(file, 1, "dump taken, no restore rehearsal")],
        remediation:
          "Restore the dump into a throwaway database, count the tables, verify the constraints, " +
          "then drop it. Do not call a backup 'taken' until the rehearsal passes.",
      });
    }
    return findings;
  },
};
