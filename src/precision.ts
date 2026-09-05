import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Finding } from "./core/finding.js";
import type { Project } from "./core/rule.js";
import { scanProject } from "./core/engine.js";
import { allRules } from "./rules.js";
import { loadRegistry, findProject } from "./registry.js";

/**
 * Measurement infrastructure. Turns the tool's real precision from a guess
 * into a number measured AGAINST A LABELLED CORPUS.
 *
 * The principle: every finding is labelled by hand once as "tp" (real) or
 * "fp" (false); from then on precision is computed DETERMINISTICALLY on every
 * run. No LLM. You cannot improve what you do not measure — make the number visible first.
 */

export type Verdict = "tp" | "fp" | "?";

export interface LabelRow {
  verdict: Verdict;
  rule: string;
  file: string;
  line: number;
  snippet?: string;
  note?: string;
}

export type Labels = Record<string, LabelRow>;

/**
 * A finding's stable identity: rule + file + EVIDENCE CONTENT.
 *
 * Satir NO tabanli kimlik, korpus projesi duzenlendiginde (satirlar
 * would invalidate every label. Content (the evidence snippet) is unaffected by
 * a line shift — same code, same identity. When there is no snippet,
 * satira duser (geriye uyumlu son care).
 */
export function fingerprint(f: Finding): string {
  const ev = f.evidence.find((e) => e.kind === "file");
  const file = ev?.file ?? "(no file)";
  const snip = (ev?.snippet ?? "").replace(/\s+/g, " ").trim().slice(0, 100);
  const anahtar = snip || `L${ev?.line ?? 0}`;
  return `${f.ruleId}::${file}::${anahtar}`;
}

export function loadLabels(path: string): Labels {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as Labels;
  } catch {
    return {};
  }
}

export function saveLabels(path: string, labels: Labels): void {
  mkdirSync(dirname(path), { recursive: true });
  // Sort the keys so diffs stay clean.
  const sirali: Labels = {};
  for (const k of Object.keys(labels).sort()) sirali[k] = labels[k];
  writeFileSync(path, JSON.stringify(sirali, null, 2) + "\n", "utf-8");
}

/** Statically scans the corpus projects and collects every finding. */
export async function collectFindings(
  projectNames: string[],
  targetsPath: string,
): Promise<{
  findings: Finding[];
  /** The unfiltered list (info included) for the regression gate. */
  allFindings: Finding[];
  scanned: string[];
  notFound: string[];
  emptyProjects: string[];
}> {
  const kayit = loadRegistry(targetsPath);
  const findings: Finding[] = [];
  /** The unfiltered list (info included) for the regression gate. */
  const allFindings: Finding[] = [];
  const scanned: string[] = [];
  const notFound: string[] = [];
  const emptyProjects: string[] = [];
  for (const ad of projectNames) {
    const p: Project | undefined = findProject(kayit, ad);
    if (!p) {
      notFound.push(ad);
      continue;
    }
    const rapor = await scanProject(p, allRules, { staticOnly: true, includeStandards: false });
    // AN UNREADABLE PROJECT IS NOT SILENTLY COUNTED AS 0: if its path is missing
    // or it has no source files at all, the denominator shrinks silently and
    // precision lies. The tool's own philosophy applies to the tool itself:
    // olcemedigin sey icin 0 dondurmek "temiz" demek degildir.
    const pathMissing = rapor.notes.some((n) => /path bulunamad|okunamad|atland/i.test(n));
    const noRules = (rapor.rulesRun?.length ?? 0) === 0;
    if (pathMissing || noRules) {
      emptyProjects.push(p.name);
      continue;
    }
    // info severity precision'a girmez: risk IDDIASI degil, bilgi notudur.
    findings.push(...rapor.findings.filter((f) => f.severity !== "info"));
    // ⚠ THE REGRESSION CHECK NEEDS A SEPARATE LIST.
    //
    // Handing the same filtered list to the regression check made info-level
    // labelled TPs look "lost" ON EVERY RUN: a missing security.txt, the .env
    // inventory, absent audit logging — all info. The gate stayed permanently
    // red and real regressions drowned in the noise. The gate must see EVERY
    // finding; filtering belongs to the precision calculation alone.
    allFindings.push(...rapor.findings);
    scanned.push(p.name);
  }
  return { findings, allFindings, scanned, notFound, emptyProjects };
}

export interface RulePrecision {
  rule: string;
  tp: number;
  fp: number;
  unlabeled: number;
  precision: number | null; // tp/(tp+fp); etiketli yoksa null
}

export interface PrecisionReport {
  perRule: RulePrecision[];
  overall: { tp: number; fp: number; unlabeled: number; precision: number | null };
}

/** Measures a set of findings against the labels. */
export function computePrecision(findings: Finding[], labels: Labels): PrecisionReport {
  const perRuleMap = new Map<string, RulePrecision>();
  const al = (rule: string): RulePrecision => {
    let r = perRuleMap.get(rule);
    if (!r) {
      r = { rule, tp: 0, fp: 0, unlabeled: 0, precision: null };
      perRuleMap.set(rule, r);
    }
    return r;
  };

  let tp = 0, fp = 0, unl = 0;
  for (const f of findings) {
    const row = al(f.ruleId);
    const lbl = labels[fingerprint(f)];
    const v = lbl?.verdict;
    if (v === "tp") { row.tp++; tp++; }
    else if (v === "fp") { row.fp++; fp++; }
    else { row.unlabeled++; unl++; }
  }

  for (const r of perRuleMap.values()) {
    r.precision = r.tp + r.fp > 0 ? r.tp / (r.tp + r.fp) : null;
  }

  const perRule = [...perRuleMap.values()].sort((a, b) => {
    // Low precision and labelled first (the ones that need fixing go on top)
    const pa = a.precision ?? 2, pb = b.precision ?? 2;
    if (pa !== pb) return pa - pb;
    return b.unlabeled - a.unlabeled;
  });

  return {
    perRule,
    overall: { tp, fp, unlabeled: unl, precision: tp + fp > 0 ? tp / (tp + fp) : null },
  };
}

/**
 * Syncs the label file with the current findings: new findings are added as
 * "?" (the user marks them tp/fp), existing verdicts are PRESERVED, and labels
 * that no longer appear are marked "stale" (never deleted — keep the history).
 */
export function syncLabels(
  findings: Finding[],
  labels: Labels,
): { labels: Labels; eklenen: number; guncel: number; stale: number } {
  const gorulen = new Set<string>();
  let eklenen = 0, guncel = 0;
  const next: Labels = { ...labels };

  for (const f of findings) {
    const fp = fingerprint(f);
    gorulen.add(fp);
    if (next[fp]) {
      guncel++;
      continue; // keep the verdict
    }
    const ev = f.evidence.find((e) => e.kind === "file");
    next[fp] = {
      verdict: "?",
      rule: f.ruleId,
      file: ev?.file ?? "(no file)",
      line: ev?.line ?? 0,
      snippet: (ev?.snippet ?? f.title).slice(0, 120),
    };
    eklenen++;
  }

  let stale = 0;
  for (const [k, row] of Object.entries(next)) {
    if (!gorulen.has(k) && row.note !== "stale") {
      // No longer firing: keep the verdict but mark it.
      next[k] = { ...row, note: row.note ? row.note : "stale" };
      stale++;
    }
  }
  return { labels: next, eklenen, guncel, stale };
}

/**
 * The CI corpus gate. A REGRESSION check against the labelled corpus:
 *   - a labelled-TP finding that NO LONGER FIRES → detection regression (the
 *     rule loosened or broke and is missing a real hole).
 *   - a labelled-FP finding that CAME BACK → FP regression (a tightening was
 *     reverted).
 * Both lower the precision already earned. CI must fail the build on either (exit 1).
 */
export interface RegressionReport {
  lostTp: LabelRow[];      // labelled-tp that no longer fires (lost detection)
  returnedFp: LabelRow[];  // labelled-fp firing again (an FP came back)
  temiz: boolean;
}

export function checkRegressions(findings: Finding[], labels: Labels): RegressionReport {
  const suanki = new Set(findings.map(fingerprint));
  const lostTp: LabelRow[] = [];
  const returnedFp: LabelRow[] = [];

  for (const [fp, row] of Object.entries(labels)) {
    const cozuldu = /çözüldü|resolved|fixed|düzeltildi/i.test(row.note ?? "");
    if (row.verdict === "tp" && cozuldu && suanki.has(fp)) {
      // A RESOLVED real hole CAME BACK -> a vulnerability regression (the fix was
      // reverted). As serious as a lost TP; we report it through lostTp.
      lostTp.push({ ...row, note: "HOLE CAME BACK: " + (row.note ?? "") });
    } else if (row.verdict === "tp" && !cozuldu && !suanki.has(fp)) {
      // An unresolved labelled real finding NO LONGER FIRES -> detection regression
      // (the rule loosened and now misses a hole that still exists). If resolved, it is a fix.
      lostTp.push(row);
    } else if (row.verdict === "fp" && suanki.has(fp) && /stale/.test(row.note ?? "")) {
      // Only a SUPPRESSED (stale) FP coming back counts as a regression. When an
      // FP is fixed, syncLabels marks it 'stale' (it no longer fires); if it fires
      // again, a tightening has been reverted. A KNOWN-still-firing FP (documented
      // rather than fixed) is the baseline, not a regression.
      returnedFp.push(row);
    }
  }
  return { lostTp, returnedFp, temiz: lostTp.length === 0 && returnedFp.length === 0 };
}
