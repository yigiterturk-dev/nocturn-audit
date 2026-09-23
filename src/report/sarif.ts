import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { ProjectReport } from "../core/engine.js";
import type { Finding } from "../core/finding.js";

/**
 * SARIF 2.1.0 output.
 *
 * Why: the HTML/JSON reports are read by a person opening a file. SARIF is what
 * GitHub Code Scanning, GitLab SAST and VS Code consume — findings appear inline
 * on PRs and in the Security tab. That is where a security tool actually changes
 * behaviour, not in a report nobody re-opens.
 *
 * Mapping: critical/high → "error", medium → "warning", low/info → "note".
 * Each rule is declared once in the driver; each finding is a result.
 */

type SarifLevel = "error" | "warning" | "note";

function sarifLevel(severity: Finding["severity"]): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

/** GitHub's security-severity scale (0.0–10.0), used for the code-scanning UI. */
function securitySeverity(severity: Finding["severity"]): string {
  switch (severity) {
    case "critical":
      return "9.0";
    case "high":
      return "7.5";
    case "medium":
      return "5.0";
    case "low":
      return "2.5";
    default:
      return "0.0";
  }
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: {
    tags: string[];
    "security-severity": string;
    precision?: string;
  };
}

export function buildSarif(reports: ProjectReport[]): unknown {
  const ruleMap = new Map<string, SarifRule>();
  const results: unknown[] = [];

  for (const report of reports) {
    for (const f of report.findings) {
      if (!ruleMap.has(f.ruleId)) {
        ruleMap.set(f.ruleId, {
          id: f.ruleId,
          name: f.ruleId,
          shortDescription: { text: f.title },
          fullDescription: {
            text: `${f.description}\n\nRemediation: ${f.remediation}`,
          },
          helpUri: f.cwe
            ? `https://cwe.mitre.org/data/definitions/${f.cwe.replace("CWE-", "")}.html`
            : undefined,
          properties: {
            tags: [f.owasp],
            "security-severity": securitySeverity(f.severity),
            precision: f.confidence,
          },
        });
      }

      const fileEv = f.evidence.find((e) => e.kind === "file");
      const httpEv = f.evidence.find((e) => e.kind === "http");
      const locations: unknown[] = [];
      if (fileEv?.file) {
        locations.push({
          physicalLocation: {
            artifactLocation: { uri: fileEv.file },
            region: fileEv.line ? { startLine: fileEv.line } : undefined,
          },
        });
      }

      results.push({
        ruleId: f.ruleId,
        level: sarifLevel(f.severity),
        message: {
          text: fileEv?.snippet
            ? `${f.title} — ${fileEv.snippet}`
            : f.title,
        },
        locations,
        properties: {
          severity: f.severity,
          confidence: f.confidence,
          cwe: f.cwe,
          project: report.project.name,
          ...(httpEv ? { http: `${httpEv.request}\n${httpEv.response}` } : {}),
        },
      });
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "nocturn-audit",
            version: "0.1.0",
            informationUri: "https://github.com/yigiterturk-dev/nocturn-audit",
            rules: [...ruleMap.values()],
          },
        },
        results,
      },
    ],
  };
}

export function writeSarifReport(
  reports: ProjectReport[],
  outPath: string,
): void {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(buildSarif(reports), null, 2), "utf8");
}
