import { describe, it, expect } from "vitest";
import { buildSarif } from "../src/report/sarif.js";
import type { ProjectReport } from "../src/core/engine.js";

function fakeReport(): ProjectReport {
  return {
    project: { name: "demo", path: "/demo", owned: false, stack: { framework: "next" } },
    findings: [
      {
        ruleId: "a03-sql-injection",
        title: "Possible SQL injection",
        owasp: "A03:2021-Injection",
        severity: "high",
        description: "A raw query is built from input.",
        remediation: "Use a parameterised query.",
        cwe: "CWE-89",
        confidence: "certain",
        evidence: [
          { kind: "file", file: "src/db/q.ts", line: 12, snippet: "db.query(`...`)" },
        ],
      },
      {
        ruleId: "a05-cors-wildcard",
        title: "CORS wildcard",
        owasp: "A05:2021-Security Misconfiguration",
        severity: "medium",
        description: "Access-Control-Allow-Origin: *",
        remediation: "Restrict the origin.",
        evidence: [
          { kind: "http", request: "GET /", response: "HTTP 200" },
        ],
      },
    ],
    counts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
    certainCounts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    heuristicCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
    score: 9,
    rulesRun: ["a03-sql-injection", "a05-cors-wildcard"],
    notes: [],
    gaps: [],
    fileDigests: {},
  };
}

describe("SARIF output", () => {
  it("declares each rule once in the driver", () => {
    const sarif = buildSarif([fakeReport()]) as any;
    const rules = sarif.runs[0].tool.driver.rules;
    expect(rules.length).toBe(2);
    expect(rules.map((r: any) => r.id)).toContain("a03-sql-injection");
  });

  it("maps severity to SARIF level", () => {
    const sarif = buildSarif([fakeReport()]) as any;
    const results = sarif.runs[0].results;
    const high = results.find((r: any) => r.ruleId === "a03-sql-injection");
    const med = results.find((r: any) => r.ruleId === "a05-cors-wildcard");
    expect(high.level).toBe("error");
    expect(med.level).toBe("warning");
  });

  it("carries file location and CWE", () => {
    const sarif = buildSarif([fakeReport()]) as any;
    const r = sarif.runs[0].results[0];
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe("src/db/q.ts");
    expect(r.locations[0].physicalLocation.region.startLine).toBe(12);
    expect(r.properties.cwe).toBe("CWE-89");
  });

  it("a finding with only HTTP evidence has no file location", () => {
    const sarif = buildSarif([fakeReport()]) as any;
    const r = sarif.runs[0].results.find((x: any) => x.ruleId === "a05-cors-wildcard");
    expect(r.locations).toEqual([]);
  });
});
