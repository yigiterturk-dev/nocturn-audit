import type { Finding } from "../core/finding.js";
import { cagrilariGez, moduldenMi, lineNo, ts, type AstFile } from "../core/ast.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A03 — dangerous execution and DOM injection:
 * dangerouslySetInnerHTML, eval, new Function, child_process (girdi ile).
 */

import type { Confidence } from "../core/finding.js";
import type { Severity } from "../core/severity.js";

type SigKind = "dom" | "eval" | "cmd";

interface Sig {
  re: RegExp;
  /**
   * This signature is derived FROM THE TREE; text search only kicks in when the
   * tree cannot be built. The value says which set of the tree to use — two
   * signatures can share a `kind` (`eval()` and `new Function()`), and if both
   * attach to one call, that call yields two findings.
   */
  treeSet?: "cmd" | "eval" | "fn";
  kind: SigKind;
  title: string;
  desc: string;
  fix: string;
}

const SIGS: Sig[] = [
  {
    re: /dangerouslySetInnerHTML/,
    kind: "dom",
    title: "dangerouslySetInnerHTML usage (XSS)",
    desc: "Raw HTML is injected via dangerouslySetInnerHTML. If the content comes from users, stored or reflected XSS is possible.",
    fix: "Sanitise the HTML (DOMPurify), or render plain text and React elements instead.",
  },
  {
    re: /\beval\s*\(/,
    kind: "eval",
    treeSet: "eval",
    title: "eval() usage",
    desc: "eval() executes dynamic code; if any input reaches it, this can escalate to remote code execution.",
    fix: "Remove eval; use JSON.parse, a safe parser, or explicit logic.",
  },
  {
    re: /new\s+Function\s*\(/,
    kind: "eval",
    treeSet: "fn",
    title: "new Function() ile dinamik kod",
    desc: "new Function(...) compiles code at runtime, carrying the same risk as eval.",
    fix: "Remove the dynamic code generation and express it as static logic.",
  },
  {
    re: /child_process|\bexec(Sync)?\s*\(|\bspawn(Sync)?\s*\(/,
    kind: "cmd",
    treeSet: "cmd",
    title: "child_process / command execution",
    desc: "A system command is executed.",
    fix: "Avoid running commands where possible; if you must, use execFile with an argument array, avoid shell:true, and validate input against an allowlist.",
  },
];

const INPUT_HINT = /(req\.|params|searchParams|query\.|body|input|props\.|formData|request\.|\$\{)/;
// USER/request-derived input (NOT a template literal or local variable — usages
// like `node ${file}` in build scripts are by design and are not escalated).
const REQUEST_INPUT = /(req\.|\breq\b|params|searchParams|query\.|\bbody\b|formData|request\.|searchParams|nextUrl|await\s+request)/;
// Strong signals that the command really is built from user input.
const CMD_TAINT = /(shell\s*:\s*true)/i;

// --- dangerouslySetInnerHTML (DOM XSS) data-flow helpers ---
// If attacker-controlled data flows into __html (tainted), this is real XSS.
const DOM_TAINT =
  /(req\.|request\.|\bparams\b|searchParams|nextUrl|query\.|\bbody\b|formData|props\.|\bprops\b|useParams|useSearchParams|\.get\(|await\s+fetch|fetch\(|cms|contentful|sanity|payload|graphql|window\.location|document\.location|location\.(search|hash|href)|getData|userInput|comment|message|description)/i;
// The value has been HTML-sanitised or escaped → downgrade or drop.
const DOM_SANITIZER =
  /(escapeJsonLd|sanitize\w*|DOMPurify|createDOMPurify|\bescapeHtml\b|\bescape\s*\(|xss\s*\(|clean\s*\()/i;

/**
 * Decides whether the `__html` value of a dangerouslySetInnerHTML sink is
 * attacker-controlled (tainted), using single-level variable resolution within
 * the file. A full data-flow inspection, not just a `role`-style name check.
 */
function htmlValueTainted(valExpr: string, content: string): boolean {
  if (DOM_TAINT.test(valExpr)) return true;
  const ids = valExpr.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? [];
  const SKIP = new Set(["JSON", "stringify", "String", "__html"]);
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  for (const id of ids) {
    if (SKIP.has(id)) continue;
    // const/let/var X = <rhs>  → is the RHS tainted?
    const asg = new RegExp(
      "(?:const|let|var)\\s+" + esc(id) + "\\s*=\\s*([^\\n;]+)",
    ).exec(content);
    if (asg) {
      // Resolves to a local const/literal assignment → safe unless the RHS is tainted.
      if (DOM_TAINT.test(asg[1])) return true;
      continue;
    }
    // Destructured prop / function parameter → prop-derived (tainted by spec:
    // a value from the parent component may be attacker-controlled).
    const destructured = new RegExp(
      "(?:function\\s+\\w+\\s*\\(|=>|\\(|,)\\s*\\{[^{}]*\\b" + esc(id) + "\\b[^{}]*\\}",
    );
    const positionalParam = new RegExp(
      "function\\s+\\w+\\s*\\([^)]*\\b" + esc(id) + "\\b|\\(\\s*" + esc(id) + "\\s*[,:)]",
    );
    if (destructured.test(content) || positionalParam.test(content)) return true;
  }
  return false;
}


/**
 * Confirm `eval` and command-execution signals FROM THE SYNTAX TREE.
 *
 * Text search was a disaster for these two signatures: in one run, roughly 100
 * of 117 findings were `regex.exec(...)` and better-sqlite3's `db.exec(...)`.
 * Both carry the `exec(` pattern and neither executes a command. On the tree
 * the question is unambiguous: does this call resolve to `child_process`?
 *
 * Returns the LINE numbers of the calls that are genuinely dangerous. The
 * existing severity and data-flow logic is unchanged; only the "does this line
 * count" decision moves to the tree.
 */
const CP_DISLARI = [
  "exec", "execSync", "execFile", "execFileSync",
  "spawn", "spawnSync", "fork",
];

function treeConfirmedLines(
  ast: AstFile | null,
): { cmd: Set<number>; eval: Set<number>; fn: Set<number> } | null {
  if (!ast) return null;
  const cmd = new Set<number>();
  const evl = new Set<number>();
  const fn = new Set<number>();
  cagrilariGez(ast, (c) => {
    if (moduldenMi(ast, c, "child_process", CP_DISLARI)) {
      cmd.add(lineNo(ast, c));
      return;
    }
    const e = c.expression;
    // eval(...) — unless shadowed by a local binding
    if (ts.isCallExpression(c) && ts.isIdentifier(e) && e.text === "eval" && !ast.ithal.has("eval")) {
      evl.add(lineNo(ast, c));
      return;
    }
    // new Function(...)
    if (ts.isNewExpression(c) && ts.isIdentifier(e) && e.text === "Function") {
      fn.add(lineNo(ast, c));
    }
  });
  // The `import { spawn } from "node:child_process"` line itself counts too:
  // the PRESENCE of command execution is inventory (reported at a low severity).
  return { cmd, eval: evl, fn };
}

export const dangerousEval: StaticRule = {
  id: "a03-dangerous-execution-sink",
  title: "Dangerous execution or DOM injection sink",
  owasp: "A03:2021-Injection",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      // DOCUMENTATION IS NOT CODE. Files whose tree cannot be built fall back to
      // text, and that is how the word `spawn` in a README became "command
      // execution". Execution sinks are not searched for in non-code files.
      if (/\.(md|mdx|txt|rst|json|ya?ml|lock|csv|tsv|html?|css|svg)$/i.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      /**
       * shadcn/ui'nin CHART bileşeni — olduğu gibi kopyalanan satıcı kodu.
       *
       * `components/ui/chart.tsx`, tema renklerini bir `<style>` etiketine
       * `dangerouslySetInnerHTML` ile basar. İçerik SABİT bir THEMES haritası +
       * config nesnesinin anahtarlarından kurulur; istek verisi girmez.
       *
       * Bu dosya binlerce projeye AYNI şekilde kopyalanıyor: portföy taramasında
       * TEK BAŞINA 6 projede "kesin HIGH" üretti (neuroscope, nocturn-hub,
       * nocturn-lifeos, voice-agent-template, nocturn-youtube-automation,
       * Aysira DM AI). Aynı satıcı dosyası için altı ayrı "acil" satırı, gerçek
       * bulguları listede görünmez yapar.
       */
      const yolNorm = file.replace(/\\/g, "/");
      const shadcnChart =
        /(^|\/)components\/ui\/chart\.(tsx|jsx)$/.test(yolNorm) &&
        /THEMES/.test(content) &&
        /data-chart=/.test(content) &&
        // Güvenlik ağı: enjekte edilen metin bir istek/parametre değerinden
        // besleniyorsa satıcı dosyası bile olsa susmayız.
        !/(req\.|request\.|searchParams|params\.|props\.html|dangerousHtml)/.test(content);
      if (shadcnChart) continue;

      const lines = content.split(/\r?\n/);
      // Tree confirmation: cmd/eval signatures count only on lines the tree
      // confirmed. When the tree cannot be built (unsupported extension, parse
      // error) we fall back to the old text behaviour — a retreat, not blindness.
      const onay = treeConfirmedLines(ctx.ast(file));
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        for (const sig of SIGS) {
          // THE TREE IS THE SOURCE, text is the fallback.
          //
          // At first the tree was used only as a FILTER: text-matched lines were
          // passed through tree confirmation. That missed aliased imports — after
          // `import { execSync as run }`, the line `run("npm ci")` contains no
          // text pattern at all, yet a command really does execute. A filter only
          // reduces false positives; the false NEGATIVE closes only when the tree
          // becomes the source.
          const agacli = !!onay && !!sig.treeSet;
          if (agacli) {
            if (!onay![sig.treeSet!].has(i + 1)) continue;
          } else if (!sig.re.test(raw)) {
            continue;
          }
          const window = lines.slice(Math.max(0, i - 2), i + 4).join("\n");
          const inputNear = INPUT_HINT.test(window);

          let severity: Severity;
          let confidence: Confidence;
          let note = "";

          if (sig.kind === "dom") {
            // dangerouslySetInnerHTML: XSS only when attacker-controlled (tainted)
            // data flows into __html. A static literal, JSON-LD or sanitised
            // content is an FP — follow the data flow.
            // A mention of `dangerouslySetInnerHTML` in a comment is not a sink; drop it.
            if (/^\s*(\*|\/\/|\/\*)/.test(raw)) continue;
            const ctxWin = lines
              .slice(Math.max(0, i - 1), i + 6)
              .join("\n");
            // 1) JSON-LD structured data → standard in React, not an HTML context.
            if (/application\/ld\+json/i.test(ctxWin)) continue;
            // 2) Extract the __html value. If absent this is not a real sink → drop.
            const hm = /__html\s*:\s*([\s\S]{0,240}?)(?:\}\s*\}|,\s*\n\s*\}|$)/.exec(
              ctxWin,
            );
            if (!hm) continue;
            const valExpr = hm[1].trim();
            if (!valExpr) continue;
            // 3) JSON.stringify(constant) → not an HTML context, safe serialisation.
            const isJsonStringify = /^JSON\.stringify\s*\(/.test(valExpr);
            // 4) If the value starts with a string/template literal and contains no
            //    interpolation (${...}), the content is fully static (even if truncated).
            const isStaticLiteral =
              /^["'`]/.test(valExpr) && !/\$\{/.test(valExpr);
            // 5) HTML-safe sanitisation or escaping has been applied.
            const sanitized = DOM_SANITIZER.test(ctxWin);
            if (isJsonStringify || isStaticLiteral || sanitized) {
              // Allowlist: static / serialised / sanitised → do not report.
              continue;
            }
            if (htmlValueTainted(valExpr, content)) {
              // Attacker-controlled data reaches the sink → real XSS.
              severity = "high";
              confidence = "certain";
              note =
                " Data from a user, request, database or CMS appears to flow into __html → XSS risk.";
            } else {
              // The source looks static and repository-local → low, verify by hand.
              severity = "low";
              confidence = "likely";
              note =
                " (The value looks static and repository-local — no attacker-controlled data detected; most likely safe.)";
            }
          } else if (sig.kind === "cmd") {
            // child_process is usually by design in build, tooling or server code.
            // Escalate only when real request/user input flows into the command (or
            // shell:true is present); do not escalate a local `${variable}`.
            const tainted = REQUEST_INPUT.test(window) || CMD_TAINT.test(window);
            severity = tainted ? "high" : "low";
            confidence = "likely";
            note = tainted
              ? " The command appears to be built from user input → command injection (RCE) risk."
              : " (Looks like a fixed tooling invocation — no user input detected; most likely intentional.)";
          } else {
            // eval / new Function — heuristic; high when input is nearby, else medium.
            severity = inputNear ? "high" : "medium";
            confidence = "likely";
            note = inputNear ? " (User input detected nearby.)" : "";
          }

          findings.push({
            ruleId: this.id,
            title: sig.title,
            owasp: this.owasp,
            severity,
            confidence,
            description: sig.desc + note,
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation: sig.fix,
          });
        }
      }
    }
    return findings;
  },
};
