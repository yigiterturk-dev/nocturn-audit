import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { DepsRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

const execFileAsync = promisify(execFile);

/**
 * A06 — vulnerable or outdated dependencies.
 * A wrapper around `npm audit --json`. Non-destructive (read-only).
 */

interface NpmAdvisory {
  name?: string;
  severity?: string;
  title?: string;
  url?: string;
  via?: Array<string | { title?: string; url?: string; severity?: string; source?: number }>;
  range?: string;
  fixAvailable?: boolean | { name?: string; version?: string };
}

const mapSeverity = (s: string | undefined): Severity => {
  switch ((s ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
};

export const npmAudit: DepsRule = {
  id: "a06-npm-audit",
  title: "Vulnerable or outdated dependency",
  owasp: "A06:2021-Vulnerable & Outdated Components",
  severity: "high",
  kind: "deps",
  // Dependency scanning: the manifest and registry access are both required.
  requires: ["npm", "net"],
  async run(ctx): Promise<Finding[]> {
    if (!ctx.exists("package.json")) return [];
    // Without a lockfile npm audit is not meaningful — report that
    const hasLock =
      ctx.exists("package-lock.json") ||
      ctx.exists("npm-shrinkwrap.json");

    let stdout = "";
    try {
      const res = await execFileAsync(
        "npm",
        ["audit", "--json", ...(hasLock ? [] : ["--package-lock-only"])],
        { cwd: ctx.root, maxBuffer: 20 * 1024 * 1024, timeout: 120_000 },
      );
      stdout = res.stdout;
    } catch (err: unknown) {
      // npm audit exits non-zero when it finds vulnerabilities, but stdout is still JSON
      const e = err as { stdout?: string; message?: string };
      if (e.stdout) stdout = e.stdout;
      else {
        return [
          {
            ruleId: this.id,
            title: "npm audit could not be run",
            owasp: this.owasp,
            severity: "info",
            description: `npm audit could not be run: ${e.message ?? "unknown error"}. It may need network access or a lockfile.`,
            evidence: [fileEvidence("package.json", 1, "npm audit failure")],
            remediation:
              "Create a lockfile with `npm install` in the project directory, then run `npm audit` by hand.",
          },
        ];
      }
    }

    let parsed: {
      vulnerabilities?: Record<string, NpmAdvisory>;
      metadata?: { vulnerabilities?: Record<string, number> };
    };
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return [
        {
          ruleId: this.id,
          title: "npm audit output could not be parsed",
          owasp: this.owasp,
          severity: "info",
          description: "The npm audit JSON output has an unexpected shape.",
          evidence: [fileEvidence("package.json", 1, "parse error")],
          remediation: "Update npm and try `npm audit --json` by hand.",
        },
      ];
    }

    // PRODUCTION vs DEV. The lesson learned: npm audit "high" counts are usually
    // inflated by dev and build tooling (electron-builder, vite, vitest, esbuild)
    // — none of which ships with the app, so none of which is a live risk.
    // `--omit=dev` audits only the production tree. A vuln that is NOT in
    // production is lowered to LOW and stamped "dev/build"; a real production
    // risk (e.g. next) stays high.
    let prodVulnPkgs: Set<string> | null = null;
    try {
      const pr = await execFileAsync(
        "npm",
        ["audit", "--json", "--omit=dev", ...(hasLock ? [] : ["--package-lock-only"])],
        { cwd: ctx.root, maxBuffer: 20 * 1024 * 1024, timeout: 120_000 },
      );
      prodVulnPkgs = new Set(Object.keys(JSON.parse(pr.stdout).vulnerabilities ?? {}));
    } catch (err: unknown) {
      const e = err as { stdout?: string };
      if (e.stdout) {
        try {
          prodVulnPkgs = new Set(Object.keys(JSON.parse(e.stdout).vulnerabilities ?? {}));
        } catch { /* if the split fails, everything stays as it is */ }
      }
    }

    const findings: Finding[] = [];
    const vulns = parsed.vulnerabilities ?? {};
    for (const [pkg, adv] of Object.entries(vulns)) {
      let severity = mapSeverity(adv.severity);
      // skip the info-level ones (noise)
      if (severity === "info") continue;
      // Not in the production tree → a dev/build dependency, never ships, LOW.
      const devOnly = prodVulnPkgs !== null && !prodVulnPkgs.has(pkg);
      if (devOnly) severity = "low";
      const viaTitles = (adv.via ?? [])
        .map((v) => (typeof v === "string" ? v : v.title))
        .filter(Boolean)
        .slice(0, 3)
        .join("; ");
      const fix =
        adv.fixAvailable === true
          ? "A fix is available: `npm audit fix`."
          : adv.fixAvailable && typeof adv.fixAvailable === "object"
            ? `Fix: ${adv.fixAvailable.name}@${adv.fixAvailable.version} (may be a breaking change).`
            : "No automatic fix — update the package by hand or find an alternative.";

      findings.push({
        ruleId: this.id,
        title: `Zafiyetli paket: ${pkg} (${adv.severity}${devOnly ? ", dev/build" : ""})`,
        owasp: this.owasp,
        severity,
        description: `npm audit ${pkg} paketinde ${adv.severity} seviyesinde zafiyet bildirdi${
          viaTitles ? `: ${viaTitles}` : ""
        }. Affected range: ${adv.range ?? "?"}.${
          devOnly
            ? " ⚠ This package is NOT in the PRODUCTION tree (a dev/build dependency such as vite, " +
              "electron-builder or a test tool); it never ships with the app, so live risk is " +
              "low. Update it anyway for the build machine and CI."
            : " This is a PRODUCTION dependency — it runs live, so it takes priority."
        }`,
        evidence: [
          fileEvidence("package.json", 1, `${pkg} — ${adv.severity} — ${adv.range ?? ""}`),
        ],
        remediation: fix,
      });
    }

    // stay quiet when there is no summary finding and the metadata is healthy
    return findings;
  },
};
