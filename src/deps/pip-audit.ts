import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { DepsRule } from "../core/rule.js";

const execFileAsync = promisify(execFile);

/**
 * A06 — vulnerable Python dependencies (a pip-audit wrapper).
 *
 * The Python counterpart of npm-audit — and a large blind spot: the tool only
 * looked at npm, so Flask/Python projects were never audited at all.
 * Real case: 13 packages in a venv carried vulnerabilities.
 * 81 bilinen zafiyet (aiohttp 14+ CVE, cryptography...) — requirements.txt
 * Because they are transitive or loosely pinned, `-r` MISSES them; auditing the
 * installed environment (the venv) is essential.
 *
 * Non-destructive (read-only). Reports informationally when pip-audit is not installed.
 */

// requirements.txt misses loose pins and transitive deps, so we prefer the
// INSTALLED environment (the venv python); failing that, -r with requirements.
function venvPython(root: string): string | null {
  for (const v of ["venv", ".venv", "env", ".env"]) {
    for (const py of ["bin/python", "bin/python3", "Scripts/python.exe"]) {
      const p = join(root, v, py);
      if (existsSync(p)) return p;
    }
  }
  return null;
}

interface PipVuln { id?: string; fix_versions?: string[]; description?: string }
interface PipDep { name?: string; version?: string; vulns?: PipVuln[] }

export const pipAudit: DepsRule = {
  id: "a06-pip-audit",
  title: "Vulnerable Python dependency",
  owasp: "A06:2021-Vulnerable & Outdated Components",
  severity: "high",
  kind: "deps",
  // Dependency scanning: the manifest and registry access are both required.
  requires: ["npm", "net"],
  async run(ctx): Promise<Finding[]> {
    const isPy =
      ctx.exists("requirements.txt") ||
      ctx.exists("pyproject.toml") ||
      ctx.exists("Pipfile") ||
      ctx.exists("setup.py");
    if (!isPy) return [];

    const py = venvPython(ctx.root);
    const cmd = py ?? "pip-audit";
    const args = py
      ? ["-m", "pip_audit", "-f", "json"]
      : ctx.exists("requirements.txt")
        ? ["-r", "requirements.txt", "-f", "json"]
        : ["-f", "json"];

    let stdout = "";
    try {
      const res = await execFileAsync(cmd, args, {
        cwd: ctx.root,
        maxBuffer: 20 * 1024 * 1024,
        timeout: 180_000,
      });
      stdout = res.stdout;
    } catch (err: unknown) {
      const e = err as { stdout?: string; code?: string; message?: string };
      // pip-audit can also exit non-zero when it finds vulnerabilities; stdout is still JSON.
      if (e.stdout && e.stdout.trim().startsWith("{")) stdout = e.stdout;
      else {
        return [{
          ruleId: this.id,
          title: "pip-audit could not be run",
          owasp: this.owasp,
          severity: "info",
          confidence: "certain",
          description:
            `This is a Python project but pip-audit could not be run (${e.message?.slice(0, 60) ?? e.code ?? "?"}). ` +
            `Dependency vulnerabilities were NOT MEASURED — this is "could not look", not "clean".`,
          evidence: [fileEvidence("requirements.txt", 1, "pip-audit yok")],
          remediation:
            "Install pip-audit (`pip install pip-audit`), activate the venv and run " +
            "`pip-audit`. Run it in CI as well.",
        }];
      }
    }

    let parsed: { dependencies?: PipDep[] } | PipDep[];
    try { parsed = JSON.parse(stdout); } catch { return []; }
    const deps: PipDep[] = Array.isArray(parsed) ? parsed : (parsed.dependencies ?? []);

    const findings: Finding[] = [];
    for (const d of deps) {
      const vulns = d.vulns ?? [];
      if (!vulns.length) continue;
      const fixes = [...new Set(vulns.flatMap((v) => v.fix_versions ?? []))].slice(0, 3);
      findings.push({
        ruleId: this.id,
        title: `Zafiyetli Python paketi: ${d.name} (${vulns.length} zafiyet)`,
        owasp: this.owasp,
        // A package with many CVEs is high; one or two is medium.
        severity: vulns.length >= 3 ? "high" : "medium",
        confidence: "likely",
        description:
          `${d.name}@${d.version} paketinde ${vulns.length} bilinen zafiyet ` +
          `(${vulns.slice(0, 3).map((v) => v.id).filter(Boolean).join(", ")}${vulns.length > 3 ? "…" : ""}). ` +
          `⚠ The LOCAL venv was audited — it may DIFFER from the deployed environment: ` +
          `this package may not be installed in production at all (a dev/tool dependency). Verify in ` +
          `the production environment (the server venv), and count only the packages that are ` +
          `actually deployed as real risk.`,
        evidence: [fileEvidence("requirements.txt", 1, `${d.name}@${d.version}`)],
        remediation:
          fixes.length
            ? `Upgrade with \`pip install -U ${d.name}\` (fixed in ${fixes.join(", ")}). Pin it in requirements.txt and upgrade on the server too.`
            : `Upgrade with \`pip install -U ${d.name}\`; if no fix exists, consider an alternative package.`,
      });
    }
    return findings;
  },
};
