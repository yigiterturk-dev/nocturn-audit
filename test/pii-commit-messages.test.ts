import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { piiInCommitMessages } from "../src/integrity/pii-in-commit-messages.js";

/**
 * Personal data in commit messages.
 *
 * A parallel session found the blind spot: every PII rule looks at FILES — data
 * files, generated output, log lines. None of them looks at the message, and the
 * message travels with the repository too.
 *
 * A REAL git repository is created instead of fixtures: message rewriting and
 * `--all` behaviour cannot be faked.
 */

function depoKur(mesajlar: string[]): string {
  const root = mkdtempSync(join(tmpdir(), "commit-pii-"));
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: root, stdio: ["ignore", "pipe", "ignore"] });
  git("init", "-q");
  git("config", "user.email", "t@example.invalid");
  git("config", "user.name", "T");
  mesajlar.forEach((mesaj, i) => {
    writeFileSync(join(root, `f${i}.txt`), String(i));
    git("add", "-A");
    git("commit", "-q", "-m", mesaj);
  });
  return root;
}

const calistir = (root: string, isGitRepo = true) =>
  piiInCommitMessages.run({
    project: { name: "t", path: root, owned: false, stack: {} },
    root: root,
    files: [],
    read: () => null,
    readHead: () => null,
    exists: () => false,
    isTracked: () => false,
    isGitRepo,
    grep: () => [],
  } as never) as Array<{ severity: string; description: string; evidence: unknown[] }>;

describe("a02 — personal data in commit messages", () => {
  it("BAD: messages containing three different addresses → finding", () => {
    // The shape from the real case: writing an address as measurement evidence.
    const root = depoKur([
      "measurement: 7900 Owasco Ave 1,188 sqft/1930 → comp signal refuted",
      "verification: top row 1004-06 Highland St, score 91.5",
      "map test: card opened (220 Stedman St, $1,321/mo)",
    ]);
    const f = calistir(root);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
    expect(f[0].description).toContain("3 distinct street address");
    expect(f[0].evidence.length).toBeGreaterThan(0);
    rmSync(root, { recursive: true, force: true });
  });

  it("CLEAN: a single occurrence does not cross the threshold", () => {
    // One address in one message may be an EXAMPLE; if the rule catches that,
    // every explanatory commit becomes a finding.
    const root = depoKur([
      "tried with the 12 Main St record as an example",
      "code cleanup",
    ]);
    expect(calistir(root).length).toBe(0);
    rmSync(root, { recursive: true, force: true });
  });

  it("CLEAN: messages containing no address", () => {
    const root = depoKur(["initial commit", "add tests", "fix bug"]);
    expect(calistir(root).length).toBe(0);
    rmSync(root, { recursive: true, force: true });
  });

  it("CLEAN: silent when this is not a git repository", () => {
    const root = depoKur(["7900 Owasco Ave", "103 Slawson Dr", "225 Russell Ave"]);
    expect(calistir(root, false).length).toBe(0);
    rmSync(root, { recursive: true, force: true });
  });

  it("the remediation text stresses doing it BEFORE PUSHING", () => {
    // Detection is cheap, the fix is expensive: rewriting messages changes every
    // hash. If the rule does not say so, people work on it at the wrong moment.
    const root = depoKur([
      "7900 Owasco Ave measurement", "103 Slawson Dr measurement", "225 Russell Ave measurement",
    ]);
    const f = calistir(root) as Array<{ remediation: string }>;
    expect(f[0].remediation).toContain("BEFORE PUSHING");
    rmSync(root, { recursive: true, force: true });
  });
});
