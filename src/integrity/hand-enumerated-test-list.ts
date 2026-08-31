import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A08 — the test command enumerates files one by one.
 *
 * A legitimate choice for controlling order and concurrency, but it has a silent
 * trap: a newly written test file that nobody adds to the list NEVER RUNS, and
 * the suite stays green. Whoever wrote the test believes it passes.
 */
const TEST_FILE_PATH = /[\w./-]+\.(test|spec)\.(ts|tsx|js|mjs|cjs)/g;

export const handEnumeratedTestList: StaticRule = {
  id: "int-hand-enumerated-test-list",
  title: "The test command enumerates files by hand; a new test silently never runs",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "certain",
  // This rule's job is to count test files; it has to see them.
  scansTests: true,
  run(ctx): Finding[] {
    const paket = ctx.read("package.json");
    if (!paket) return [];
    let scripts: Record<string, string>;
    try {
      scripts = (JSON.parse(paket) as { scripts?: Record<string, string> }).scripts || {};
    } catch {
      return [];
    }

    const findings: Finding[] = [];
    for (const [ad, komut] of Object.entries(scripts)) {
      const sayilan = [...komut.matchAll(TEST_FILE_PATH)].map((m) => m[0]);
      if (sayilan.length < 3) continue;

      // Are the test files on disk present in the list?
      const diskteki = ctx.files.filter((f) => /\.(test|spec)\.(ts|tsx|js|mjs|cjs)$/.test(f));
      const eksik = diskteki.filter((f) => !komut.includes(f));

      findings.push({
        ruleId: "int-hand-enumerated-test-list",
        title: "The test command enumerates files by hand; a new test silently never runs",
        owasp: "A08:2021-Software & Data Integrity Failures",
        severity: eksik.length ? "high" : "medium",
        confidence: "certain",
        description:
          `The \`${ad}\` command lists ${sayilan.length} test file(s) by hand.` +
          (eksik.length
            ? ` ${eksik.length} file(s) exist on disk but are MISSING from the list — those tests never run: ${eksik.slice(0, 6).join(", ")}`
            : " Nothing is missing right now, but any new test not added to the list will silently not run."),
        evidence: [fileEvidence("package.json", 1, `"${ad}": ...${sayilan.length} dosya`)],
        remediation:
          "Add a test that compares the list against the directory BOTH ways: it should fail on files " +
          "on disk but not in the list, and on files in the list but not on disk.",
      });
    }
    return findings;
  },
};
