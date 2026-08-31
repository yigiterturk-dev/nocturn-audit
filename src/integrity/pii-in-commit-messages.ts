import { execFileSync } from "node:child_process";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A02 — personal data in COMMIT MESSAGES.
 *
 * The PII rules look at files: data files, generated output, log lines. None of
 * them looks at a commit message — and messages travel with the repository too.
 *
 * Real case: a harvester's commit messages carried ten real property addresses
 * as measurement evidence ("7900 Owasco 1,188 sqft/1930 → comp signal refuted").
 * They were useful notes; nobody thought of them as personal data.
 *
 * Detection is cheap but THE FIX IS EXPENSIVE: `filter-repo --path` does not
 * clean messages, you have to rewrite all of them, and that changes every
 * commit's hash. So the severity stays medium — marking something expensive to
 * fix as "critical" makes the list unreadable — while the remediation text
 * stresses one thing: catch it BEFORE PUSHING.
 */

const ADRES_DESENLERI = [
  /\b\d{1,6}\s+[A-Z][A-Za-z]{2,}\s+(St|Street|Ave|Avenue|Rd|Road|Dr|Drive|Ln|Lane|Blvd|Boulevard|Ct|Court|Way|Pl|Place|Ter|Cir|Hwy|Pkwy)\b/g,
  /\b[A-ZÇĞİÖŞÜ][\wçğıöşü]{2,}\s+(Mah\.?|Mahallesi|Sok\.?|Sokak|Cad\.?|Caddesi)\b/g,
];

/** One occurrence may be prose; several mean data. */
const ESIK = 3;

const AYIRICI = "<<<NOCTURN-COMMIT>>>";

export const piiInCommitMessages: StaticRule = {
  id: "a02-pii-in-commit-messages",
  title: "Personal data in commit messages",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "medium",
  kind: "static",
  // Without git history and tracking information this rule can measure NOTHING.
  // Returning `[]` outside a repository would read as "clean" — but nothing was looked at.
  requires: ["git"],
  confidence: "certain",
  cwe: "CWE-359",
  run(ctx: StaticContext): Finding[] {
    if (!ctx.isGitRepo) return [];

    let cikti: string;
    try {
      cikti = execFileSync("git", ["log", "--all", `--pretty=${AYIRICI}%H%n%B`], {
        cwd: ctx.root,
        encoding: "utf8",
        timeout: 60_000,
        maxBuffer: 32 * 1024 * 1024,
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch {
      return [];
    }

    const findings = new Map<string, Set<string>>();
    for (const blok of cikti.split(AYIRICI)) {
      const lineEnd = blok.indexOf("\n");
      if (lineEnd < 0) continue;
      const karma = blok.slice(0, lineEnd).trim().slice(0, 8);
      const body = blok.slice(lineEnd + 1);
      if (!karma) continue;
      for (const desen of ADRES_DESENLERI) {
        for (const m of body.matchAll(desen)) {
          if (!findings.has(karma)) findings.set(karma, new Set());
          findings.get(karma)!.add(m[0].trim());
        }
      }
    }

    const toplam = new Set<string>();
    for (const kume of findings.values()) for (const adres of kume) toplam.add(adres);
    if (toplam.size < ESIK) return [];

    return [{
      ruleId: "a02-pii-in-commit-messages",
      title: "Personal data in commit messages",
      owasp: "A02:2021-Cryptographic Failures",
      severity: "medium",
      confidence: "certain",
      cwe: "CWE-359",
      description:
        `${findings.size} commit message(s) contain ${toplam.size} distinct street address(es) ` +
        `(e.g. ${[...toplam].slice(0, 3).join(", ")}). Messages travel with the repository, and no ` +
        "file scan ever looks there — neither `git rm --cached` nor `filter-repo --path` touches " +
        "them.",
      evidence: [...findings.entries()].slice(0, 3).map(([karma, kume]) =>
        fileEvidence(`commit ${karma}`, 1, [...kume].slice(0, 2).join(" · "))),
      remediation:
        "Catch this BEFORE PUSHING — at that point rewriting messages with `git rebase -i` or " +
        "`git filter-repo --message-callback` is cheap. After a push it is expensive: " +
        "every hash changes, clones break, and remote copies have already been taken. " +
        "The durable fix is to tie evidence to a record IDENTIFIER instead of prose: a parcel number, not an address.",
    }];
  },
};
