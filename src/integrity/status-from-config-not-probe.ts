import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A09 — connection status derived FROM CONFIGURATION, not from a real call.
 *
 * "Is the setting present?" and "does the service answer?" are two different
 * questions. The code asks the first and displays the answer to the second: if
 * the environment variable is defined, the dashboard says "connected".
 *
 * Real case: a document scanner was dead for two days — the service had been
 * skipped at startup and was also configured with the wrong protocol, so it
 * could never connect. The dashboard said "ClamAV connected" the whole time,
 * because it only looked at whether the environment variable existed. Document
 * hâldeydi ve kimse fark etmedi.
 *
 * The distinction: saying "configured" is honest, saying "connected" is a
 * MEASUREMENT claim. A claim that is not measured should not be made.
 */

/**
 * Text carrying a connection or health claim.
 *
 * ⚠ NO `\b` HERE. In JavaScript a word boundary only knows ASCII letters, and
 * because the Turkish word `bağlı` ends in `ı`, `\bbağlı\b` NEVER matched.
 * That is exactly why the first version of this rule could not see Turkish
 * claims and missed the very line it was written for.
 *
 * The second attempt checked the boundary OUTSIDE the string, and this time
 * missed a word starting immediately after the quote (`"connected"`). The
 * correct approach: extract the string, then check the boundary INSIDE it — so
 * both the start and compound words such as `disconnected` are handled.
 */
const LETTERS = "A-Za-zÇĞİÖŞÜçğıöşü";
const DIZELER = /"([^"\n]*)"|'([^'\n]*)'|`([^`\n]*)`/g;
const ANAHTAR = new RegExp(
  `(^|[^${LETTERS}])(bağlı|baglı|bagli|connected|live|healthy|online|reachable|available|çalışıyor|calisiyor|aktif)([^${LETTERS}]|$)`,
  "i",
);

/** Does one of the strings on this line carry a connection claim? */
function hasClaim(line: string): boolean {
  DIZELER.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DIZELER.exec(line)) !== null) {
    const content = m[1] ?? m[2] ?? m[3] ?? "";
    if (ANAHTAR.test(content)) return true;
  }
  return false;
}

/** Expressions that only measure THE PRESENCE OF A SETTING. */
const AYAR_KONTROLU = new RegExp([
  // helpers shaped like `xConfigured()` / `xEnabled()`
  "\\w*[Cc]onfigured\\s*\\(\\s*\\)",
  "\\w*[Ee]nabled\\s*\\(\\s*\\)",
  // Forms that ask whether an environment variable EXISTS.
  //
  // The first version knew only `process.env.X ?` and `Boolean(process.env.X)`
  // and missed the most common one — `if (!process.env.X)`.
  "Boolean\\s*\\(\\s*process\\.env",
  "!!?\\s*process\\.env\\.\\w+",
  "if\\s*\\(\\s*!?\\s*process\\.env\\.\\w+",
  "process\\.env\\.\\w+\\s*(\\?|&&|\\|\\||\\))",
].join("|"));

/** Signals that a real probe took place. */
const GERCEK_YOKLAMA =
  /(await\s+\w*(ping|probe|check|connect|query|scan|fetch|request|health)\w*\s*\(|\.connect\s*\(|createConnection|\.query\s*\(|fetch\s*\()/i;

export const statusFromConfigNotProbe: StaticRule = {
  id: "int-status-from-config-not-probe",
  title: "Connection status is derived from configuration, not from a real call",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.(ts|tsx|js|mjs|cjs|py)$/.test(file)) continue;
      if (/\.(test|spec)\./.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        if (!/\breturn\b/.test(line)) continue;
        if (!hasClaim(line)) continue;

        // In the window ABOVE this claim, what is the decision based on?
        const pencere = lines.slice(Math.max(0, i - 8), i + 1).join("\n");
        if (!AYAR_KONTROLU.test(pencere)) continue;
        // If a real probe exists in the same function, the claim may be measured.
        const body = lines.slice(Math.max(0, i - 20), i + 6).join("\n");
        if (GERCEK_YOKLAMA.test(body)) continue;

        findings.push({
          ruleId: "int-status-from-config-not-probe",
          title: "Connection status is derived from configuration, not from a real call",
          owasp: "A09:2021-Security Logging & Monitoring Failures",
          severity: "medium",
          confidence: "likely",
          description:
            `\`${file}:${i + 1}\` returns a connection or health claim, but the decision rests only on ` +
            "THE PRESENCE OF A SETTING; nothing anywhere actually touches the service. " +
            "If the service died, this line would keep saying the same thing.",
          evidence: [fileEvidence(file, i + 1, line.trim().slice(0, 140))],
          remediation:
            "Either probe it FOR REAL (connect, send a small request, return the result), or shrink the " +
            "claim: saying \"configured\" is honest, saying \"connected\" is a measurement claim. " +
            "Also give the monitor a check that measures BEHAVIOUR rather than configuration.",
        });
        break;
      }
    }
    return findings;
  },
};
