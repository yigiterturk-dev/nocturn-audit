import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A04 — a PAID API called in a loop with NO UPPER BOUND.
 *
 * When a paid API (OpenAI, Anthropic, Cohere, Apify) is called while iterating
 * a list of variable length and the loop has no CAP, a data anomaly — a list
 * far larger than expected, a deleted profile, a reset database — triggers
 * thousands of paid calls in a single run and blows up the bill.
 *
 *
 * Real case: a listing-tagging job (Anthropic) had no per-run cap, and because
 * days_on_zillow was 91% None the recency filter did not protect it either. Had
 * the database been reset, 1,583 listings would have been tagged in one run
 * (~317 calls). The fix: `if len(candidates) > THRESHOLD: skip`.
 *
 * This rule flags a paid API call INSIDE a for/while loop when the same
 * function contains no cap or limit check.
 */

const PAID_API =
  /(openai|anthropic|\.messages\.create|chat\.completions|cohere|replicate|\.generate\(|apify|pyzill|elevenlabs|deepgram|assemblyai|\.embeddings\.create)/i;

const LOOP = /^\s*(for\s+\w+|for\s*\(|while\s+|while\s*\(|\.map\s*\(|\.forEach\s*\(|Promise\.all)/;

// A cap or upper-bound signal in the same function or block
const CAP_HINT =
  /(\bcap\b|_cap|limit|LIMIT|max_|_max|azami|esik|ESIK|threshold|batch_size|\[:\s*\d|slice\(0|\.slice\(|head\(|take\(|break\b|budget|kota|quota)/i;

const isSourceLike = (f: string) =>
  /\.(py|js|ts|mjs|cjs|rb|go)$/.test(f) && !/(test|spec|conftest|fixtures?)/.test(f);

export const unboundedPaidLoop: StaticRule = {
  id: "a04-unbounded-paid-loop",
  title: "Paid API called in a loop with no upper bound (billing risk)",
  owasp: "A04:2021-Insecure Design",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // ONE-HOP WRAPPER RESOLUTION (2026-09-24): the common shape is a local
    // wrapper (`jevSkorla`) whose body calls the paid API, and the LOOP calls
    // the wrapper. The allowlist above only matched the library call itself,
    // so wrapped loops were invisible (recall suite: lib/toplu-analiz.ts).
    // Phase 1: any function whose body contains a paid call is a wrapper name.
    const sarmalayici = new Set<string>();
    for (const m of ctx.grep(PAID_API)) {
      if (!isSourceLike(m.file)) continue;
      const content = ctx.read(m.file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      for (let i = m.line - 1; i >= Math.max(0, m.line - 40); i--) {
        const l = lines[i] ?? "";
        const head =
          /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([\w$]+)/.exec(l) ??
          /^\s*(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?\(/.exec(l) ??
          /^\s*(?:async\s+)?([\w$]+)\s*\([^)]*\)\s*:\s*[\w<>\[\]| ]+\s*\{/.exec(l);
        if (head) {
          sarmalayici.add(head[1]);
          break;
        }
      }
    }
    // Phase 2: calls to those wrapper names count as paid calls too.
    const hits = [
      ...ctx.grep(PAID_API),
      ...(sarmalayici.size
        ? ctx.grep(
            new RegExp(`\\b(${[...sarmalayici].map((a) => a.replace(/\$/g, "\\$")).join("|")})\\s*\\(`),
          )
        : []),
    ];

    const flagged = new Set<string>();

    for (const m of hits) {
      if (!isSourceLike(m.file)) continue;
      if (flagged.has(m.file)) continue;
      const content = ctx.read(m.file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      // Is there a loop ABOVE this paid call (in the same function)?
      // Simple: scan up to 40 lines upwards looking for a loop header; if the
      // indentation holds between the loop and the call, the call is inside it.
      let inLoop = false;
      let loopLine = 0;
      for (let i = m.line - 1; i >= Math.max(0, m.line - 40); i--) {
        if (LOOP.test(lines[i] ?? "")) {
          inLoop = true;
          loopLine = i + 1;
          break;
        }
        // stop if we hit a function boundary
        if (/^\s*(def |function |const \w+\s*=\s*(async\s*)?\()/.test(lines[i] ?? "")) break;
      }
      if (!inLoop) continue;

      // Is there a cap or limit in the function body? (±30 lines around the call)
      const pencere = lines
        .slice(Math.max(0, loopLine - 8), m.line + 8)
        .join("\n");
      if (CAP_HINT.test(pencere)) continue;

      // A DEAD MODULE (the safe case): the file is imported NOWHERE and is not a
      // directly executed entry point either (no if __name__ == "__main__"). Then
      // the code never runs -> not a live billing risk. A worker.py run by systemd
      // does contain `__main__` -> it is KEPT (no false negative). In one project
      // an apify_zillow.py was exactly this: the system used pyzill, and apify was
      // neither imported nor executed.
      const entryPoint = /if\s+__name__\s*==\s*['"]__main__['"]|\bfunc main\b|^\s*def main\s*\(\s*\)\s*:/m.test(content);
      if (!entryPoint) {
        const modBase = (m.file.replace(/\\/g, "/").split("/").pop() ?? "").replace(/\.[^.]+$/, "");
        if (modBase) {
          // DEAD-MODULE DETECTION MUST KNOW BOTH ECOSYSTEMS.
          //
          // This pattern only knew Python import syntax, so
          // (`import x`, `from x import y`). TypeScript'in
          // `import { f } from "../lib/client"` did not match — meaning EVERY paid
          // loop in a TS project was mistaken for a "dead module" and skipped.
          // The canary caught it: the fixture produced no finding even though it
          // was called from a live route.
          const importRe = new RegExp(
            "(^|\\n)\\s*(import\\s+[\\w.]*\\b" + modBase +
              "\\b|from\\s+[\\w.]*\\b" + modBase + "\\b\\s+import)" +
              "|from\\s+['\"`][^'\"`]*\\b" + modBase + "(\\.[jt]sx?)?['\"`]" +
              "|require\\s*\\(\\s*['\"`][^'\"`]*\\b" + modBase + "(\\.[jt]sx?)?['\"`]",
          );
          const importEden = ctx
            .grep(importRe)
            .filter((h) => h.file !== m.file && !/(test|spec|conftest|\.md$)/i.test(h.file));
          if (importEden.length === 0) continue; // dead module -> skip
        }
      }

      flagged.add(m.file);
      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "medium",
        description:
          `${m.file}:${m.line} calls a paid API (${lines[m.line - 1]?.trim().slice(0, 60)}) ` +
          `inside a loop (line ${loopLine}) with no visible UPPER BOUND ` +
          `(cap/limit/batch/break/slice). If the list grows unexpectedly ` +
          `(a data anomaly, a reset database) a single run can fire an enormous ` +
          `tetiklenip fatura patlar.`,
        evidence: [fileEvidence(m.file, m.line, "paid API inside a loop")],
        remediation:
          "Put a hard cap before the loop (e.g. `if len(items) > THRESHOLD: " +
          "log and skip`), or a per-batch limit plus a total quota. A filter " +
          "(such as recency) is not enough on its own — an anomaly can defeat it too.",
      });
    }
    return findings;
  },
};
