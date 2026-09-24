#!/usr/bin/env node
import "dotenv/config";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { loadRegistry, findProject } from "./registry.js";
import { scanProject, hasCritical, type ProjectReport } from "./core/engine.js";
import { analyzeFindingWithLLM } from "./core/llm.js";
import { allRules } from "./rules.js";
import { printReport, printStandards } from "./report/terminal.js";
import { standardsChecks } from "./standards/index.js";
import { writeHtmlReport } from "./report/html.js";
import { writeJsonReport } from "./report/json.js";
import { writeSarifReport } from "./report/sarif.js";
import { SEVERITY_ORDER } from "./core/severity.js";
import { runInvariants } from "./invariants.js";
import {
  collectFindings, computePrecision, loadLabels, saveLabels, syncLabels, checkRegressions,
} from "./precision.js";
import { measureRecall, formatRecallReport, recallPaths } from "./recall.js";
import { computeDiff, readReport } from "./diff.js";
import { scaffoldRule } from "./scaffold.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
// dist/cli.js → the project root is one level up
const PROJECT_ROOT = resolve(__dirname, "..");

function targetsPath(custom?: string): string {
  if (custom) return resolve(custom);
  // cwd first, then the tool root
  const cwdT = resolve(process.cwd(), "targets.json");
  if (existsSync(cwdT)) return cwdT;
  return join(PROJECT_ROOT, "targets.json");
}

/**
 * The report file name follows the LOCAL day.
 *
 * `toISOString()` returns UTC: at 03:00 local time the UTC day has already
 * rolled over and the report is written to "tomorrow's" file. This misled me
 * personally — I scanned at night, read the previous day's file, thought the
 * false positives I had fixed were still there, and set about "fixing" the rule
 * again. People live their day in local time; the file name should too.
 */
function dateStamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

const program = new Command();

program
  .name("nocturn-audit")
  .description(
    "Multi-project security audit tool based on OWASP Top 10 2021 (detection and reporting only)",
  )
  .version(
    // Read from package.json so the CLI can never report a version that is not
    // the one installed — a hardcoded string silently lies after every bump.
    JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ).version as string,
  );

program
  .command("scan")
  .description("Scan projects (static + live + dependencies)")
  .argument("[project]", "scan only this project (by name)")
  .option("--static", "static code scan only (never touch the live host)")
  .option("--live-only", "live HTTP probes only")
  .option("--no-deps", "skip the npm audit step")
  .option("--no-standards", "skip the standards profile")
  .option("-t, --targets <path>", "path to targets.json")
  .option("-v, --verbose", "print every finding to the terminal")
  .option("--ai", "triage findings with an LLM (high/critical only)")
  .option("-c, --concurrency <n>", "scan up to N projects in parallel (default 1)", "1")
  .action(async (projectName, opts) => {
    const tPath = targetsPath(opts.targets);
    if (!existsSync(tPath)) {
      console.error(
        pc.red(`targets.json not found: ${tPath}\n`) +
          pc.dim("See targets.example.json for the format, or pass a path with -t."),
      );
      process.exit(2);
    }

    let projects = loadRegistry(tPath);
    if (projects.length === 0) {
      console.error(pc.red("targets.json contains no projects."));
      process.exit(2);
    }

    if (projectName) {
      const p = findProject(projects, projectName);
      if (!p) {
        console.error(
          pc.red(`Project not found: ${projectName}`) +
            pc.dim(`\nRegistered: ${projects.map((x) => x.name).join(", ")}`),
        );
        process.exit(2);
      }
      projects = [p];
    }

    const scanOpts = {
      staticOnly: opts.static === true,
      liveOnly: opts.liveOnly === true,
      includeDeps:
        opts.deps === false ? false : opts.static || opts.liveOnly ? false : true,
      includeStandards: opts.standards !== false,
    };

    if (scanOpts.staticOnly && scanOpts.liveOnly) {
      console.error(pc.red("--static and --live-only cannot be combined."));
      process.exit(2);
    }

    console.log(
      pc.dim(
        `\nScanning ${projects.length} project(s) · mode: ${
          scanOpts.staticOnly ? "static" : scanOpts.liveOnly ? "live-only" : "full"
        }`,
      ),
    );

    const concurrency = Math.max(1, parseInt(opts.concurrency, 10) || 1);
    const reports: ProjectReport[] = [];
    // A bounded worker pool: projects are scanned in parallel up to the
    // concurrency limit, but the report order stays the input order.
    let cursor = 0;
    const worker = async (): Promise<void> => {
      while (cursor < projects.length) {
        const idx = cursor++;
        const project = projects[idx];
        process.stdout.write(pc.dim(`  → ${project.name} … `));
        const report = await scanProject(project, allRules, scanOpts);
      
      if (opts.ai && report.findings.length > 0) {
        process.stdout.write(pc.yellow(`\n    [LLM] triaging high-risk findings...\n`));
        for (const finding of report.findings) {
          if (finding.severity === "high" || finding.severity === "critical") {
            process.stdout.write(pc.dim(`      → ${finding.title} ... `));
            const filePath = finding.evidence[0]?.file;
            const fileContent = (filePath && existsSync(filePath)) ? readFileSync(filePath, "utf8") : "";
            const analysis = await analyzeFindingWithLLM(finding, fileContent);
            if (analysis) {
               if (analysis.isRealThreat) {
                 finding.description += `\n\n[LLM: CONFIRMED REAL THREAT]:\n${analysis.explanation}`;
                 if (analysis.remediationCode) {
                   finding.remediation += `\n\n[LLM: SUGGESTED FIX]:\n${analysis.remediationCode}`;
                 }
                 process.stdout.write(pc.red(`confirmed\n`));
               } else {
                 finding.description += `\n\n[LLM: FALSE POSITIVE]:\n${analysis.explanation}`;
                 finding.severity = "low";
                 finding.confidence = "likely";
                 process.stdout.write(pc.green(`false positive (downgraded)\n`));
               }
            } else {
               process.stdout.write(pc.dim(`skipped (no API key or request failed)\n`));
            }
          }
        }
      }

      // sort findings by severity
      report.findings.sort(
        (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
      );
      reports[idx] = report;
      console.log(
        pc.dim(
          `\n    Result: ${report.findings.length} finding(s) (${report.counts.critical}C/${report.counts.high}H · certain ${report.certainCounts.critical}C/${report.certainCounts.high}H)`,
        ),
      );
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(concurrency, projects.length) }, worker),
    );

    printReport(reports, opts.verbose === true);

    // write reports
    const stamp = dateStamp();
    const htmlPath = join(process.cwd(), "report", `${stamp}.html`);
    const jsonPath = join(process.cwd(), "report", `${stamp}.json`);
    const sarifPath = join(process.cwd(), "report", `${stamp}.sarif`);
    writeHtmlReport(reports, htmlPath, stamp);
    writeJsonReport(reports, jsonPath);
    writeSarifReport(reports, sarifPath);
    console.log(pc.dim(`  Report: ${htmlPath}`));
    console.log(pc.dim(`        ${jsonPath}`));
    console.log(pc.dim(`        ${sarifPath}  (SARIF — GitHub Code Scanning / GitLab SAST)`));
    console.log(pc.dim(`        Upload: gh api -X POST repos/{owner}/{repo}/code-scanning/sarifs -f input_file=${sarifPath}\n`));

    if (hasCritical(reports)) {
      console.log(pc.red("  Critical findings present → exit 1"));
      process.exit(1);
    }
    process.exit(0);
  });

program
  .command("init")
  .description("Create a targets.json for the current project")
  .option("-t, --targets <path>", "where to write targets.json", "targets.json")
  .option("--url <url>", "live URL of this project (enables live probes only with --owned)")
  .option("--owned", "you are authorised to send live probes to this URL")
  .action((opts) => {
    const out = resolve(opts.targets);
    if (existsSync(out)) {
      console.error(pc.red(`Refusing to overwrite an existing file: ${out}`));
      process.exit(2);
    }
    const root = process.cwd();
    let name = root.split("/").filter(Boolean).pop() ?? "my-project";
    const pkgPath = join(root, "package.json");
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
        if (typeof pkg.name === "string" && pkg.name) name = pkg.name.replace(/^@[^/]+\//, "");
      } catch { /* fall back to the directory name */ }
    }
    const project: Record<string, unknown> = { name, path: root, owned: opts.owned === true };
    if (opts.url) project.url = opts.url;
    const doc = {
      $comment:
        "Live probes run ONLY against targets with owned:true. Keep owned:false unless you are authorised to test that host.",
      projects: [project],
    };
    writeFileSync(out, JSON.stringify(doc, null, 2) + "\n");
    console.log("");
    console.log(pc.green(`  ✓ Wrote ${out}`));
    console.log(pc.dim(`    project: ${name}  ·  path: ${root}  ·  owned: ${project.owned}`));
    console.log("");
    console.log(pc.bold("  Next:"));
    console.log("    nocturn-audit scan            # scan everything in targets.json");
    console.log("    nocturn-audit rules           # see the active rule set");
    if (!opts.owned)
      console.log(pc.dim("\n  Live HTTP probes stay off until you set owned:true on a host you control."));
    console.log("");
  });

program
  .command("list")
  .description("List registered projects")
  .option("-t, --targets <path>", "path to targets.json")
  .action((opts) => {
    const tPath = targetsPath(opts.targets);
    if (!existsSync(tPath)) {
      console.error(pc.red(`targets.json not found: ${tPath}`));
      process.exit(2);
    }
    const projects = loadRegistry(tPath);
    console.log("");
    console.log(pc.bold(`  Registered projects (${projects.length}) — ${tPath}`));
    console.log(pc.dim("  ───────────────────────────────────────────"));
    for (const p of projects) {
      const owned = p.owned ? pc.green("owned ") : pc.dim("static");
      const stack = [p.stack.framework, p.stack.db, p.stack.auth]
        .filter((x) => x && x !== "unknown")
        .join("/");
      const pathOk = existsSync(p.path) ? "" : pc.red(" [path missing]");
      console.log(
        `  ${owned}  ${pc.bold(p.name.padEnd(18))} ${pc.dim(stack.padEnd(20))} ${
          p.url ? pc.cyan(p.url) : pc.dim("(no url)")
        }${pathOk}`,
      );
    }
    console.log("");
  });

program
  .command("standards")
  .description(
    "Standards profile — security + performance checklist (static only, writes no report file)",
  )
  .argument("[project]", "audit this project (by name); omit to list the checks instead")
  .option("-t, --targets <path>", "path to targets.json")
  .action(async (projectName, opts) => {
    // No project given: list the active check set.
    if (!projectName) {
      console.log("");
      console.log(pc.bold(`  Standards profile — active checks (${standardsChecks.length})`));
      console.log(pc.dim("  ───────────────────────────────────────────"));
      for (const cat of ["security", "performance"] as const) {
        console.log("");
        console.log(pc.yellow(cat === "security" ? "  SECURITY" : "  PERFORMANCE"));
        for (const c of standardsChecks.filter((x) => x.category === cat)) {
          const lvl =
            c.level === "critical" ? pc.red("critical") : c.level === "warning" ? pc.yellow("warning ") : pc.dim("info    ");
          console.log(`    ${lvl} ${pc.dim(c.id.padEnd(28))} ${c.title}`);
        }
      }
      console.log("");
      console.log(pc.dim("  Run it against a project: nocturn-audit standards <project>"));
      console.log("");
      return;
    }

    const tPath = targetsPath(opts.targets);
    if (!existsSync(tPath)) {
      console.error(pc.red(`targets.json not found: ${tPath}`));
      process.exit(2);
    }
    const projects = loadRegistry(tPath);
    const p = findProject(projects, projectName);
    if (!p) {
      console.error(
        pc.red(`Project not found: ${projectName}`) +
          pc.dim(`\nRegistered: ${projects.map((x) => x.name).join(", ")}`),
      );
      process.exit(2);
    }

    // Standards profile only: no OWASP rules, no deps, no live probes.
    // Writes NO report file, so it cannot overwrite the daily security
    // report and pollute the finding history.
    const report = await scanProject(p, [], {
      staticOnly: true,
      includeDeps: false,
      includeStandards: true,
    });
    for (const note of report.notes) console.log(pc.dim(`  · ${note}`));
    // Unmeasured rules get their own line so they never read as "clean".
    if (report.gaps.length) {
      const grup = new Map<string, number>();
      for (const b of report.gaps) grup.set(b.reason, (grup.get(b.reason) ?? 0) + 1);
      for (const [reason, count] of grup)
        console.log(pc.yellow(`  ⃠ not measured: ${count} rule(s) did not run — ${reason}`));
    }
    if (!report.standards) {
      console.error(pc.red("Could not build the standards profile (the project path may be missing)."));
      process.exit(2);
    }
    printStandards(p.name, report.standards);
    const kritikKaldi = report.standards.checks.some(
      (c) => c.status === "open" && c.level === "critical",
    );
    process.exit(kritikKaldi ? 1 : 0);
  });

program
  .command("rules")
  .description("List the active rule set")
  .action(() => {
    console.log("");
    console.log(pc.bold(`  Active rules (${allRules.length})`));
    console.log(pc.dim("  ───────────────────────────────────────────"));
    const byOwasp = new Map<string, typeof allRules>();
    for (const r of allRules) {
      if (!byOwasp.has(r.owasp)) byOwasp.set(r.owasp, []);
      byOwasp.get(r.owasp)!.push(r);
    }
    const cats = [...byOwasp.keys()].sort();
    for (const cat of cats) {
      console.log("");
      console.log(pc.yellow(`  ${cat}`));
      for (const r of byOwasp.get(cat)!) {
        const kind =
          r.kind === "static"
            ? pc.blue("static")
            : r.kind === "live"
              ? pc.magenta("live  ")
              : pc.green("deps  ");
        const cwe = r.cwe ? pc.dim(` [${r.cwe}]`) : "";
        // Rule default confidence (a finding may override it).
        const conf =
          r.confidence === "certain"
            ? pc.red("certain")
            : pc.dim("likely ");
        console.log(
          `    ${kind} ${conf} ${pc.dim(r.id.padEnd(34))} ${r.title}${cwe}`,
        );
      }
    }
    console.log("");
  });

program
  .command("new-rule")
  .alias("yeni-kural")
  .description("Scaffold a new rule (rule + BAD/CLEAN tests + registry entry)")
  .argument("<id>", "rule id, e.g. a01-example-rule / int-example-rule")
  .action((id: string) => {
    const result = scaffoldRule(id);
    if (result.warning) {
      console.error(pc.red(`  ${result.warning}`));
      process.exit(2);
    }
    console.log("");
    console.log(pc.green(`  ✓ Scaffold created: ${id}`));
    for (const y of result.written) console.log(pc.dim(`    ${y}`));
    console.log("");
    console.log(pc.bold("  Next — the rule stays red until all three are done:"));
    console.log("    1. Write the detection. If the question is structural (what does this");
    console.log("       call target, where does this value come from), use " + pc.bold("ctx.ast(file)") + " instead of text search.");
    console.log("    2. Fill in the BAD and CLEAN fixtures. CLEAN is the hard one:");
    console.log("       false positives are born in the 'looks like it but is safe' case.");
    console.log("    3. Review the " + pc.bold("requires") + " declaration (an empty array is a valid one).");
    console.log("");
    console.log(pc.dim("  When you tighten a rule, add a field-shaped example under test/canary/:"));
    console.log(pc.dim("  a fixture is what the author imagined; the canary is what the field looks like."));
    console.log("");
  });

program
  .command("diff")
  .alias("fark")
  .description(
    "Diff two reports — and ask whether the findings that vanished were REALLY fixed",
  )
  .argument("<before>", "previous report (report/YYYY-MM-DD.json)")
  .argument("<after>", "later report")
  .action((beforePath: string, afterPath: string) => {
    const onceki = readReport(resolve(beforePath));
    const sonraki = readReport(resolve(afterPath));
    const f = computeDiff(onceki, sonraki);

    console.log("");
    console.log(pc.bold("  Report diff"));
    console.log(pc.dim("  ───────────────────────────────────────────"));
    console.log(`  ${pc.red("+")} new:     ${f.yeni.length}`);
    console.log(`  ${pc.green("−")} vanished: ${f.vanished.length}`);
    console.log("");

    if (f.suspicious.length) {
      console.log(
        pc.yellow(
          `  ⚠ ${f.suspicious.length} finding(s) vanished while THE FILE NEVER CHANGED — these are NOT fixes.`,
        ),
      );
      console.log(
        pc.dim(
          "    If the code is identical, what changed is the rule. The hole is probably still there.",
        ),
      );
      for (const k of f.suspicious.slice(0, 20)) {
        console.log(
          `    ${pc.yellow("?")} ${pc.bold(k.project)} ${k.ruleId} — ${k.file}:${k.line}`,
        );
        if (k.snippet) console.log(pc.dim(`      ${k.snippet.slice(0, 90)}`));
      }
      if (f.suspicious.length > 20)
        console.log(pc.dim(`    … +${f.suspicious.length - 20} more`));
      console.log("");
    }

    const real = f.vanished.filter((k) => k.reason !== "file-identical");
    if (real.length) {
      console.log(pc.green(`  ✓ ${real.length} finding(s) vanished with a changed file (these may be real fixes).`));
      console.log("");
    }

    if (f.yeni.length) {
      console.log(pc.bold("  New findings:"));
      for (const y of f.yeni.slice(0, 15))
        console.log(`    ${pc.red("+")} ${pc.bold(y.project)} ${y.severity.padEnd(8)} ${y.ruleId} — ${y.file}:${y.line}`);
      if (f.yeni.length > 15) console.log(pc.dim(`    … +${f.yeni.length - 15} more`));
      console.log("");
    }

    // Exit 1 on suspicious disappearances so CI never celebrates "fewer findings".
    if (f.suspicious.length) process.exit(1);
  });

program
  .command("precision")
  .description("Measure rule precision against a labelled corpus")
  .argument("[projects...]", "corpus projects (defaults to corpus/projects.json)")
  .option("-t, --targets <path>", "path to targets.json")
  .option("--labels <path>", "label file (default corpus/labels.json)")
  .option("--corpus <path>", "corpus project list (default corpus/projects.json)")
  .option("--update", "add new findings to the label file as '?' (keep existing verdicts)")
  .option("--ci", "regression gate: exit 1 if a labelled TP stops firing or a retired FP returns")
  .action(async (projectsArg, opts) => {
    const tPath = targetsPath(opts.targets);
    const labelsPath = opts.labels
      ? resolve(opts.labels)
      : join(PROJECT_ROOT, "corpus", "labels.json");
    const corpusPath = opts.corpus
      ? resolve(opts.corpus)
      : join(PROJECT_ROOT, "corpus", "projects.json");

    // Corpus projects: argument wins over corpus/projects.json
    let projects: string[] = projectsArg && projectsArg.length ? projectsArg : [];
    if (projects.length === 0 && existsSync(corpusPath)) {
      try {
        projects = JSON.parse(readFileSync(corpusPath, "utf-8"));
      } catch {
        projects = [];
      }
    }
    if (projects.length === 0) {
      console.error(
        pc.red("The corpus is empty.") +
          pc.dim(` Pass project names, or create ${corpusPath} (an array of names).`),
      );
      process.exit(2);
    }

    console.log(pc.dim(`\nScanning corpus: ${projects.join(", ")} (static)`));
    const { findings, allFindings, scanned, notFound, emptyProjects } = await collectFindings(
      projects,
      tPath,
    );
    if (notFound.length) {
      console.log(pc.yellow(`  ⚠ not found in the registry: ${notFound.join(", ")}`));
    }
    if (emptyProjects.length) {
      console.log(pc.red(`  ⛔ UNREADABLE corpus project (missing path / 0 files): ${emptyProjects.join(", ")}`));
      console.log(pc.dim(`     These were EXCLUDED from precision — not silently counted as "clean". Fix the path in targets.json.`));
    }

    let labels = loadLabels(labelsPath);

    if (opts.update) {
      const r = syncLabels(findings, labels);
      labels = r.labels;
      saveLabels(labelsPath, labels);
      console.log(
        pc.green(`\n  Label file updated: ${labelsPath}`) +
          `\n  ${pc.dim("added (?)")}: ${r.eklenen}   ${pc.dim("existing")}: ${r.guncel}   ${pc.dim("stale")}: ${r.stale}`,
      );
      if (r.eklenen > 0) {
        console.log(
          pc.dim(`\n  Now turn the "?" verdicts in ${labelsPath} into "tp"/"fp", then run 'precision' again.`),
        );
      }
    }

    if (opts.ci) {
      // The gate sees the UNFILTERED list: info-level labelled TPs
      // (security.txt, .env inventory, audit logging) kept looking
      // like they had disappeared.
      const reg = checkRegressions(allFindings, labels);
      console.log("");
      if (reg.temiz) {
        console.log(pc.green("  ✓ CI GATE PASSED — no regression"));
        console.log(pc.dim(`    ${Object.values(labels).filter((r) => r.verdict === "tp").length} labelled TP(s) still firing, no retired FP came back.`));
        console.log("");
        return;
      }
      console.log(pc.red(pc.bold("  ⛔ CI GATE FAILED — regression detected")));
      if (reg.lostTp.length) {
        console.log(pc.red(`\n  LOST DETECTION (${reg.lostTp.length}) — a labelled real finding no longer fires:`));
        for (const r of reg.lostTp) console.log(pc.red(`    - ${r.rule}  ${r.file}:${r.line}`));
      }
      if (reg.returnedFp.length) {
        console.log(pc.red(`\n  FP RETURNED (${reg.returnedFp.length}) — a retired false positive fires again:`));
        for (const r of reg.returnedFp) console.log(pc.red(`    - ${r.rule}  ${r.file}:${r.line}`));
      }
      console.log(pc.dim("\n    A rule change lowered precision. Fix the rule, or update the label.\n"));
      process.exit(1);
    }

    const rep = computePrecision(findings, labels);
    const pct = (v: number | null): string =>
      v === null ? pc.dim("  —  ") : `${(v * 100).toFixed(0).padStart(3)}%`;

    console.log("");
    console.log(pc.bold(`  Rule precision — ${scanned.length} project(s), ${findings.length} finding(s)`));
    console.log(pc.dim("  ────────────────────────────────────────────────────────────"));
    console.log(
      pc.dim("  " + "rule".padEnd(34) + "  tp   fp  unlabeled  prec."),
    );
    for (const r of rep.perRule) {
      const isabet = pct(r.precision);
      const boya =
        r.precision === null
          ? (x: string) => x
          : r.precision < 0.5
            ? pc.red
            : r.precision < 0.8
              ? pc.yellow
              : pc.green;
      console.log(
        "  " +
          r.rule.padEnd(34) +
          String(r.tp).padStart(4) +
          String(r.fp).padStart(5) +
          String(r.unlabeled).padStart(11) +
          "   " +
          boya(isabet),
      );
    }
    console.log(pc.dim("  ────────────────────────────────────────────────────────────"));
    const o = rep.overall;
    console.log(
      pc.bold("  TOTAL".padEnd(36)) +
        String(o.tp).padStart(4) +
        String(o.fp).padStart(5) +
        String(o.unlabeled).padStart(11) +
        "   " +
        (o.precision === null ? pc.dim("  —  ") : pc.bold(pct(o.precision))),
    );
    if (o.unlabeled > 0) {
      console.log(
        pc.dim(`\n  ${o.unlabeled} finding(s) unlabeled. Add them with '--update', then mark tp/fp in labels.json.`),
      );
    }
    console.log("");
  });

program
  .command("recall")
  .description("Measure rule recall against the known-true fixture suite")
  .option("--manifest <path>", "manifest file (default corpus/recall/manifest.json)")
  .option("--fixtures <path>", "fixtures dir (default corpus/recall/fixtures)")
  .option("--min <pct>", "CI gate: fail if recall is below this percent", parseFloat)
  .option("--ci", "regression gate: exit 1 if recall drops below --min (default: last measured baseline)")
  .action(async (opts) => {
    const paths = recallPaths(PROJECT_ROOT);
    const manifestPath = opts.manifest ? resolve(opts.manifest) : paths.manifest;
    const fixturesDir = opts.fixtures ? resolve(opts.fixtures) : paths.fixtures;

    let min = opts.min as number | undefined;
    if (!min && opts.ci) {
      const baselinePath = join(PROJECT_ROOT, "corpus", "recall", "baseline.json");
      if (existsSync(baselinePath)) {
        try {
          min = JSON.parse(readFileSync(baselinePath, "utf-8")).minRecallPct;
        } catch { /* gate falls through to explicit --min */ }
      }
    }

    console.log(pc.dim(`\nRecall suite: ${manifestPath}`));
    let res;
    try {
      res = await measureRecall(manifestPath, fixturesDir);
    } catch (e) {
      console.error(pc.red(`  ⛔ ${(e as Error).message}`));
      process.exit(2);
    }
    console.log(formatRecallReport(res));

    if (opts.ci) {
      if (min == null) {
        console.error(pc.red("  ⛔ CI gate needs --min <pct> (or corpus/recall/baseline.json)."));
        process.exit(2);
      }
      if (res.recall * 100 >= min) {
        console.log(pc.green(`  ✓ RECALL GATE PASSED — ${((res.recall) * 100).toFixed(1)}% ≥ ${min}%`));
        console.log("");
        return;
      }
      console.error(pc.red(`  ⛔ RECALL GATE FAILED — ${((res.recall) * 100).toFixed(1)}% < ${min}%`));
      process.exit(1);
    }
  });

program
  .command("invariants")
  .description("Runtime invariant check — measure a live database")
  .argument("<db>", "path to the SQLite database file")
  .action((dbPath) => {
    const path = resolve(dbPath);
    console.log(pc.dim(`\nInvariant check: ${path}`));
    const findings = runInvariants(path);
    console.log("");
    let problems = 0;
    for (const b of findings) {
      const boya = b.severity === "high" ? pc.red : b.severity === "medium" ? pc.yellow : pc.dim;
      if (b.severity !== "low") problems++;
      console.log(`  ${boya(b.severity.toUpperCase().padEnd(7))} ${b.invariant}: ${b.detail}`);
    }
    console.log(pc.dim(`\n  ${problems} problem(s). (Deterministic — no LLM involved.)\n`));
    if (problems > 0) process.exit(1);
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(pc.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
  process.exit(2);
});
