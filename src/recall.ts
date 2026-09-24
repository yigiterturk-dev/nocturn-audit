import { readFileSync, existsSync } from "node:fs";
import { basename, join } from "node:path";
import pc from "picocolors";
import type { Project } from "./core/rule.js";
import { scanProject } from "./core/engine.js";
import { allRules } from "./rules.js";

/**
 * Recall measurement — the mirror of precision.ts.
 *
 * Precision says "how often are we RIGHT when we speak".
 * Recall says "how much of the ground truth do we even SEE".
 *
 * The ground truth here is a fixture suite: each fixture is a small file
 * containing EXACTLY ONE known-true vulnerability, with the expected rule id
 * recorded in the manifest. A fixture the scanner misses is a blind spot —
 * counted, printed, and gated in CI so the number can only go up.
 */

export interface RecallEntry {
  /** Fixture file name relative to the fixtures dir. */
  file: string;
  /** The rule that MUST fire on this fixture. */
  ruleId: string;
  note?: string;
}

export interface RecallManifest {
  description?: string;
  entries: RecallEntry[];
}

export interface RecallRow {
  entry: RecallEntry;
  hit: boolean;
}

export interface RecallResult {
  rows: RecallRow[];
  total: number;
  hits: number;
  /** 0..1 */
  recall: number;
  perRule: Array<{ ruleId: string; total: number; hits: number }>;
  findingsCount: number;
  notes: string[];
}

/** The fixtures live on the tool's home turf: Next.js + Supabase + NextAuth. */
const FIXTURE_STACK = { framework: "next", db: "supabase", auth: "next-auth" } as const;

function findingKey(ruleId: string, file: string): string {
  return `${ruleId}::${file.replace(/\\/g, "/")}`;
}

export async function measureRecall(
  manifestPath: string,
  fixturesDir: string,
): Promise<RecallResult> {
  if (!existsSync(manifestPath)) throw new Error(`Manifest bulunamadı: ${manifestPath}`);
  if (!existsSync(fixturesDir)) throw new Error(`Fixture dizini bulunamadı: ${fixturesDir}`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf-8")) as RecallManifest;
  if (!Array.isArray(manifest.entries) || manifest.entries.length === 0) {
    throw new Error("Manifest boş — recall ölçülemez.");
  }

  const project: Project = {
    name: "recall-fixtures",
    path: fixturesDir,
    owned: true,
    stack: { ...FIXTURE_STACK },
  };
  const report = await scanProject(project, allRules, {
    staticOnly: true,
    includeStandards: false,
  });

  const index = new Set<string>();
  for (const f of report.findings ?? []) {
    const ev = f.evidence.find((e) => e.kind === "file");
    if (!ev?.file) continue;
    index.add(findingKey(f.ruleId, ev.file));
  }

  const rows: RecallRow[] = manifest.entries.map((entry) => {
    const wanted = entry.file.replace(/\\/g, "/");
    let hit = false;
    for (const key of index) {
      const sep = key.indexOf("::");
      const ruleId = key.slice(0, sep);
      const file = key.slice(sep + 2);
      if (ruleId === entry.ruleId && file.endsWith(wanted)) {
        hit = true;
        break;
      }
    }
    return { entry, hit };
  });

  const perRuleMap = new Map<string, { total: number; hits: number }>();
  for (const r of rows) {
    const cur = perRuleMap.get(r.entry.ruleId) ?? { total: 0, hits: 0 };
    cur.total++;
    if (r.hit) cur.hits++;
    perRuleMap.set(r.entry.ruleId, cur);
  }

  const hits = rows.filter((r) => r.hit).length;
  return {
    rows,
    total: rows.length,
    hits,
    recall: rows.length ? hits / rows.length : 0,
    perRule: [...perRuleMap.entries()]
      .map(([ruleId, v]) => ({ ruleId, ...v }))
      .sort((a, b) => a.hits / a.total - b.hits / b.total || a.ruleId.localeCompare(b.ruleId)),
    findingsCount: (report.findings ?? []).length,
    notes: report.notes ?? [],
  };
}

export function formatRecallReport(res: RecallResult): string {
  const lines: string[] = [];
  const pct = (res.recall * 100).toFixed(1);
  lines.push("");
  lines.push(pc.bold(`  Recall: ${pct}%  (${res.hits}/${res.total} bilinen-gerçek bulgu yakalandı)`));
  lines.push(pc.dim(`  scanner fixtures üzerinde ${res.findingsCount} bulgu üretti`));
  lines.push("");
  lines.push(pc.dim("  kural bazında (en kötüden):"));
  for (const r of res.perRule) {
    const full = r.hits === r.total;
    const mark = full ? pc.green("✓") : pc.yellow("△");
    const ratio = full ? "" : pc.dim(` — ${r.hits}/${r.total}`);
    lines.push(`    ${mark} ${r.ruleId}${ratio}`);
  }
  const missed = res.rows.filter((r) => !r.hit);
  if (missed.length) {
    lines.push("");
    lines.push(pc.red("  KAÇIRILANLAR (kör nokta adayları):"));
    for (const m of missed) {
      lines.push(pc.red(`    ✗ ${m.entry.ruleId}  ← ${basename(m.entry.file)}${m.entry.note ? pc.dim(`  (${m.entry.note})`) : ""}`));
    }
  }
  lines.push("");
  return lines.join("\n");
}

/** Default paths relative to the package root. */
export function recallPaths(root: string): { manifest: string; fixtures: string } {
  return {
    manifest: join(root, "corpus", "recall", "manifest.json"),
    fixtures: join(root, "corpus", "recall", "fixtures"),
  };
}
