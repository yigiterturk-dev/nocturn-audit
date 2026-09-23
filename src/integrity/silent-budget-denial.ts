import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A paid-call budget that, once exhausted, silently becomes a NEGATIVE ANSWER.
 *
 * Real case (gelecekfinans.com, 2026-09-02). A news pipeline asked a model
 * "are these two reports the same event?" before it would write an article.
 * The helper started with:
 *
 *     if (judgeBudget <= 0) return false;   // ← the whole bug
 *
 * The cap was 8 calls per run. A run had ~20 topics × up to 3 candidates, so
 * after the eighth question every remaining topic got `false` — WITHOUT the
 * model ever being asked. Downstream, `false` means "not the same event", which
 * means "no second source", which means the article is never written.
 *
 * Measurement: of 112 questions, only 29 reached the model. 83 were answered by
 * the budget guard. Runs with 12 and 14 topics produced ZERO articles while runs
 * with 1-3 topics produced articles — the signature was in the logs the whole
 * time, but nobody could read it, because the log recorded a budget skip and a
 * genuine model rejection IDENTICALLY. The bottleneck was misdiagnosed for weeks
 * as "the judge is too strict" and the gate was nearly loosened over it.
 * A single call cost $0.00011: the pipeline was throwing away three quarters of
 * its work to save two cents a day.
 *
 * The same shape hides in `catch { return false }` around a paid call: a quota
 * error, a network blip or an unparsable response all collapse into what reads
 * as a deliberate "no".
 *
 * A budget IS correct — an unbounded paid loop is its own bug (see
 * a04-unbounded-paid-loop). What is wrong is that exhaustion is INVISIBLE and
 * INDISTINGUISHABLE from a real decision. The rule fires when the guard neither
 * counts nor logs nor throws: it just answers on the model's behalf.
 */

/** `budget`, `remaining`, `quota`, `kalan`, `bütçe`… — an exhaustible counter. */
const BUDGET_NAME = /(budget|bütçe|butce|quota|kota|remaining|kalan|credits?|tokensLeft|callsLeft)/i;

/**
 * A guard that answers negatively when the counter is spent:
 *   if (judgeBudget <= 0) return false;
 *   if (!budget.available()) return null;
 *   if (remaining < 1) return [];
 */
const GUARD = new RegExp(
  String.raw`\bif\s*\(\s*!?\s*([A-Za-z_$][\w$.]*)\s*` +
    String.raw`(?:<=\s*0|<\s*1|===\s*0|\.available\(\)|\.hasRemaining\(\))?\s*\)\s*` +
    String.raw`(?:\{\s*)?return\s+(false|null|\[\]|undefined)\s*;`,
);

/** Bookkeeping that makes exhaustion visible. */
const OBSERVED =
  /(skipped|atlan|log|Log|LOG|record|report|metric|counter|\+\+|\+=\s*1|throw|warn|emit|track)/;

/** A paid call nearby — the guard only matters when it is standing in for one. */
const PAID_CALL =
  /(openai|anthropic|deepseek|\.messages\.|\.responses\.|\.completions\.|\.chat\.|generateText|embed|\bllm\b|\bmodel\b)/i;

const isSourceLike = (f: string) =>
  /\.(ts|tsx|js|mjs)$/.test(f) && !/(test|spec|\.d\.ts|node_modules|dist|build)/.test(f);

export const silentBudgetDenial: StaticRule = {
  id: "int-silent-budget-denial",
  title: "An exhausted paid-call budget silently answers 'no' on the model's behalf",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "medium",
  kind: "static",
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const hits = ctx.grep(GUARD, isSourceLike);

    for (const hit of hits) {
      const counter = GUARD.exec(hit.text)?.[1];
      if (!counter || !BUDGET_NAME.test(counter)) continue;

      const content = ctx.read(hit.file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      const index = hit.line - 1;

      // The guard must actually stand in for a paid call: look for one in the
      // enclosing function. A budget guarding a free code path is fine.
      const from = Math.max(0, index - 40);
      const to = Math.min(lines.length, index + 60);
      const around = lines.slice(from, to).join("\n");
      if (!PAID_CALL.test(around)) continue;

      // Is the exhaustion recorded anywhere? Count/log/throw in the guard body
      // or on the two lines around it means somebody can still see it happen.
      const window = lines.slice(Math.max(0, index - 2), index + 3).join("\n");
      if (OBSERVED.test(window)) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "medium",
        description:
          `${hit.file}:${hit.line} — when \`${counter}\` runs out, the function returns ` +
          `a negative answer without asking the model and without recording that it ` +
          `skipped. Downstream, that value is indistinguishable from a real decision: ` +
          `the log shows a rejection where in fact nothing was ever evaluated. ` +
          `A gate built this way silently stops doing its job as soon as volume grows — ` +
          `and the busier the run, the more it rejects, so the failure looks like ` +
          `"the gate is too strict" and gets misdiagnosed for weeks.`,
        evidence: [fileEvidence(hit.file, hit.line, hit.text.trim().slice(0, 100))],
        remediation:
          "Count the three outcomes separately: DECIDED (the model answered), " +
          "SKIPPED (the budget was spent) and FAILED (quota, network, unparsable " +
          "output). Expose the skip/failure counters and write them into the run log " +
          "next to the verdicts, so an exhausted budget can never again be read as a " +
          "decision. Then check the cap against a real run — one that is below actual " +
          "volume throws away finished work to save a trivial amount of money.",
      });
    }
    return findings;
  },
};
