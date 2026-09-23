import type { Finding } from "../core/finding.js";
import type { StaticContext } from "../core/rule.js";
import type { StandardsCheck } from "./types.js";
import { hardcodedStatus } from "../integrity/hardcoded-status.js";
import { handEnumeratedTestList } from "../integrity/hand-enumerated-test-list.js";
import { generatedFileHandEdited } from "../integrity/generated-file-hand-edited.js";
import { scopeHandEnumerated } from "../integrity/scope-hand-enumerated.js";
import { updateGuardWithoutDelete } from "../integrity/update-guard-without-delete.js";
import { sessionRevokeMissing } from "../integrity/session-revoke-missing.js";
import { backupWithoutRestoreRehearsal } from "../integrity/backup-without-restore-rehearsal.js";
import { alertTargetMissing } from "../integrity/alert-target-missing.js";
import { staticPageStrictCsp } from "../integrity/static-page-strict-csp.js";
import { scanAfterWrite } from "../integrity/scan-after-write.js";

/**
 * Standards profile — INTEGRITY checks.
 *
 * Source: a real audit list. The security rules ask "can someone get in"; the
 * items here ask **"is the system telling the truth about itself?"**
 *
 *
 * Part of the list is deliberately MANUAL. A static scan cannot answer whether a
 * button in a provider dashboard is set, or whether a negative test was actually
 * run. Dropping the non-automatable item from the list is the fastest way to
 * forget it — so they stay visible and they do not lower the score.
 */

/** A wrapper turning an `int-*` rule into a checklist check. */
const kuraldan = (
  id: string,
  title: string,
  level: StandardsCheck["level"],
  rule: { run(ctx: StaticContext): Finding[] | Promise<Finding[]> },
  description: string,
  remediation: string,
  uygulanabilir?: (ctx: StaticContext) => boolean,
): StandardsCheck => ({
  id,
  title,
  category: "integrity",
  level,
  description,
  remediation,
  async run(ctx) {
    if (uygulanabilir && !uygulanabilir(ctx)) {
      return { status: "na", detail: "Not meaningful for this project." };
    }
    // A rule may be sync or async; both are accepted.
    const findings = await rule.run(ctx);
    if (!findings.length) return { status: "pass", detail: description };
    return {
      status: "open",
      detail: findings[0].description,
      evidence: findings[0].evidence,
    };
  },
});

/** An item to verify by hand — a static scan cannot answer it. */
const elle = (
  id: string,
  title: string,
  description: string,
  remediation: string,
): StandardsCheck => ({
  id,
  title,
  category: "integrity",
  level: "warning",
  description,
  remediation,
  run() {
    return { status: "manual", detail: description };
  },
});

export const integrityChecks: StandardsCheck[] = [
  // ---- CLAIMS --------------------------------------------------------------
  kuraldan(
    "integrity-status-measured",
    "Status shown on screen is measured",
    "warning",
    hardcodedStatus,
    "Health and connection status come from a real measurement, not a hardcoded value.",
    "Derive the value from a measurement: open the connection, probe the service. If it cannot be measured, return 'unknown'.",
  ),
  elle(
    "integrity-negative-test",
    "Guards passed a negative test",
    "Was every protective test watched FAILING once the thing it protects was deliberately broken?",
    "Remove the guard, run the test, watch it fail, put the guard back. A passing test is no proof that it measures anything.",
  ),
  elle(
    "integrity-numbers-derived",
    "Reported numbers are derived from their source",
    "Do the counters in tests and in the UI come from a measurement rather than a hand-written constant?",
    "Derive the number from the file or schema that produces it. A hand-written counter keeps passing after the thing it counts disappears.",
  ),

  // ---- IDENTITY AND SESSIONS -----------------------------------------------
  kuraldan(
    "integrity-revoke-ends-session",
    "Revoking access also ends open sessions",
    "critical",
    sessionRevokeMissing,
    "Password changes and access revocations also invalidate that person's open sessions.",
    "Every path that revokes access should call session invalidation, while keeping the acting user's own session alive.",
  ),

  // ---- RECORD INTEGRITY ----------------------------------------------------
  kuraldan(
    "integrity-delete-guard",
    "Immutability guards cover both UPDATE and DELETE",
    "critical",
    updateGuardWithoutDelete,
    "Every table closed to updates is closed to deletes too.",
    "Write the DELETE counterpart of every immutability trigger, and allow corrections through a reversing entry.",
    (ctx) => ctx.files.some((f) => /\.sql$/.test(f)),
  ),

  // ---- AUTHORISATION AND DATA SCOPE ----------------------------------------
  kuraldan(
    "integrity-scope-derived",
    "The data scoper derives its keys",
    "critical",
    scopeHandEnumerated,
    "Scoping does not depend on a hand-listed set of keys; a new collection is covered automatically.",
    "Derive the keys from the schema or type, and write a leak test that walks the entire response.",
  ),

  // ---- THE RUNNING SYSTEM --------------------------------------------------
  kuraldan(
    "integrity-backup-rehearsal",
    "Backups pass a restore rehearsal",
    "critical",
    backupWithoutRestoreRehearsal,
    "The dump is verified by restoring it into a throwaway database.",
    "Restore the dump, count the tables, verify the constraints. A backup is not 'taken' until the rehearsal passes.",
    (ctx) => ctx.files.some((f) => /(backup|yedek|dump)/i.test(f)),
  ),
  kuraldan(
    "integrity-alert-target",
    "The monitor has an alert target",
    "warning",
    alertTargetMissing,
    "The watchdog sends what it finds to an actual channel.",
    "Configure an alert target — a monitor without one just reports to itself.",
    (ctx) => ctx.files.some((f) => /(watchdog|monitor|healthcheck|nöbetçi)/i.test(f)),
  ),
  elle(
    "integrity-monitor-last-run",
    "The monitor's LAST RUN result was read",
    "Was the last run confirmed SUCCESSFUL, rather than merely confirming the timer exists?",
    "Run `systemctl is-failed <service>` or its equivalent. A timer existing says nothing about the run passing.",
  ),
  elle(
    "integrity-health-called-by-hand",
    "Health endpoints were called by hand",
    "Were the production health endpoints actually requested (do they return 200)?",
    "A single curl is enough. Seeing them defined is not seeing them answer.",
  ),
  elle(
    "integrity-dependent-services",
    "Dependent services actually respond",
    "Were dependencies like the scanner, queue or cache exercised with a real operation?",
    "Measure BEHAVIOUR, not configuration: run a real scan or queue job.",
  ),

  // ---- TARAYICI ------------------------------------------------------------
  kuraldan(
    "integrity-static-page-csp",
    "No page is statically generated under a strict-dynamic CSP",
    "warning",
    staticPageStrictCsp,
    "Pages are tied to request time, so a CSP nonce can be emitted.",
    "Bind the page to the request with `connection()` or `force-dynamic`; afterwards the script count must equal the nonce count.",
  ),
  elle(
    "integrity-looked-in-browser",
    "The product was opened in a browser and looked at",
    "Were the screens actually opened and read (rather than trusting a text scan)?",
    "Open the page, check the console, compare script and nonce counts. Three detectors can say 'clean' while the screen says otherwise.",
  ),

  // ---- INPUT AND STORAGE ---------------------------------------------------
  kuraldan(
    "integrity-scan-before-write",
    "Malware scanning happens BEFORE the write",
    "critical",
    scanAfterWrite,
    "An uploaded file is scanned before it is written to storage.",
    "Scan first and never write bytes that did not come back clean.",
    (ctx) => ctx.grep(/scan|clamav|malware/i).length > 0,
  ),
  elle(
    "integrity-bucket-public-url",
    "The bucket's public URL is disabled",
    "Was the bucket's public URL (e.g. Cloudflare `r2.dev`) confirmed DISABLED in the provider dashboard?",
    "Check it in the provider dashboard. This switch cannot be tested from outside, and while it is on every document and backup is world-readable.",
  ),

  // ---- PROCESS TRAPS -------------------------------------------------------
  kuraldan(
    "integrity-generated-file",
    "No hand edits inside generated files",
    "warning",
    generatedFileHandEdited,
    "Nothing is hand-added to generated files; anything extra lives in a separate additions file.",
    "Move hand-written content into its own file, have the generator include it, and test that it survives regeneration.",
  ),
  kuraldan(
    "integrity-test-list",
    "The test command does not enumerate files by hand",
    "warning",
    handEnumeratedTestList,
    "Tests are collected with a glob, so a new test file runs on its own.",
    "Use a glob. A hand-written list silently skips every new test someone forgets to add.",
    (ctx) => ctx.exists("package.json"),
  ),
];
