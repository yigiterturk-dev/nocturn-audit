import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { ProjectReport } from "../core/engine.js";

export interface JsonReport {
  tool: string;
  version: string;
  generatedAt: string;
  totals: {
    projects: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    score: number;
    /** Severity counts by confidence (a backwards-compatible extra field). */
    certain?: ProjectReport["counts"];
    heuristic?: ProjectReport["counts"];
  };
  projects: Array<{
    name: string;
    path: string;
    url?: string;
    owned: boolean;
    stack: ProjectReport["project"]["stack"];
    counts: ProjectReport["counts"];
    /** Severity counts by confidence (backwards-compatible extra fields). */
    certainCounts?: ProjectReport["counts"];
    heuristicCounts?: ProjectReport["counts"];
    score: number;
    rulesRun: string[];
    notes: string[];
    /** Rules that never ran because a precondition was unmet. */
    gaps: { ruleId: string; ruleTitle: string; requirement: string; reason: string }[];
    /** Content digest of the files behind findings — to tell "fixed" from "detection lost". */
    fileDigests: Record<string, string>;
    findings: ProjectReport["findings"];
    /**
     * The standards profile (security + performance checklist).
     * Backwards-compatible and optional — older consumers ignore it.
     */
    standards?: ProjectReport["standards"];
  }>;
}

function addCounts(
  a: ProjectReport["counts"],
  b: ProjectReport["counts"],
): void {
  a.critical += b.critical;
  a.high += b.high;
  a.medium += b.medium;
  a.low += b.low;
  a.info += b.info;
}

export function buildJson(reports: ProjectReport[]): JsonReport {
  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0, score: 0 };
  const certain = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const heuristic = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of reports) {
    totals.critical += r.counts.critical;
    totals.high += r.counts.high;
    totals.medium += r.counts.medium;
    totals.low += r.counts.low;
    totals.info += r.counts.info;
    totals.score += r.score;
    addCounts(certain, r.certainCounts);
    addCounts(heuristic, r.heuristicCounts);
  }
  return {
    tool: "nocturn-audit",
    version: "0.1.0",
    generatedAt: new Date().toISOString(),
    totals: { projects: reports.length, ...totals, certain, heuristic },
    projects: reports.map((r) => ({
      name: r.project.name,
      path: r.project.path,
      url: r.project.url,
      owned: r.project.owned,
      stack: r.project.stack,
      counts: r.counts,
      certainCounts: r.certainCounts,
      heuristicCounts: r.heuristicCounts,
      score: r.score,
      rulesRun: r.rulesRun,
      notes: r.notes,
      gaps: r.gaps,
      fileDigests: r.fileDigests,
      findings: r.findings,
      standards: r.standards,
    })),
  };
}

export function writeJsonReport(
  reports: ProjectReport[],
  outPath: string,
): void {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(buildJson(reports), null, 2), "utf8");
}
