import { readFileSync } from "node:fs";

/**
 * THE DIFF BETWEEN TWO REPORTS — and the real question: why did the finding disappear?
 *
 * The most dangerous moment for an audit tool is when a finding vanishes
 * quietly. "It was fixed" and "I can no longer see it" look identical on screen.
 *
 * This happened first-hand: three lines were written to add a brake to an SSRF
 * hole, the next run showed no finding, and it looked fixed. In fact the rule's
 * ±6 line window had shifted — the brake was never recognised and the hole was
 * still there. It only came to light by reading the code by hand.
 *
 * What makes the distinction is the file's CONTENT DIGEST: if the finding is
 * gone but the file never changed, what changed is the rule, not the code. This
 * is how the tool learns to be sceptical about its own fixes.
 */

export interface FarkBulgusu {
  ruleId: string;
  title: string;
  severity: string;
  file: string;
  line: number;
  snippet: string;
  project: string;
}

export type DisappearanceReason =
  /** The file changed — probably a real fix. */
  | "file-changed"
  /** The file was deleted or moved. */
  | "file-missing"
  /** The file is IDENTICAL but the finding is gone → the rule changed, not the code. SUSPICIOUS. */
  | "file-identical";

export interface Vanished extends FarkBulgusu {
  reason: DisappearanceReason;
}

export interface FarkSonucu {
  yeni: FarkBulgusu[];
  vanished: Vanished[];
  /** Findings that vanished although the file did not change — NOT counted as fixes. */
  suspicious: Vanished[];
}

interface RaporProjesi {
  project?: { name?: string };
  name?: string;
  findings: Array<{
    ruleId: string;
    title: string;
    severity: string;
    evidence?: Array<{ kind?: string; file?: string; line?: number; snippet?: string }>;
  }>;
  fileDigests?: Record<string, string>;
}

interface Rapor {
  projects: RaporProjesi[];
}

function projectName(p: RaporProjesi): string {
  return p.project?.name ?? p.name ?? "(isimsiz)";
}

/** A finding's stable identity — independent of line numbers (code shifts). */
function kimlik(project: string, f: RaporProjesi["findings"][number]): string {
  const ev = (f.evidence ?? []).find((e) => e.kind === "file");
  const snip = (ev?.snippet ?? "").replace(/\s+/g, " ").trim().slice(0, 100);
  return `${project}::${f.ruleId}::${ev?.file ?? "-"}::${snip || `L${ev?.line ?? 0}`}`;
}

function duzlestir(r: Rapor): Map<string, FarkBulgusu> {
  const harita = new Map<string, FarkBulgusu>();
  for (const p of r.projects) {
    const ad = projectName(p);
    for (const f of p.findings ?? []) {
      const ev = (f.evidence ?? []).find((e) => e.kind === "file");
      harita.set(kimlik(ad, f), {
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        file: ev?.file ?? "-",
        line: ev?.line ?? 0,
        snippet: (ev?.snippet ?? "").trim(),
        project: ad,
      });
    }
  }
  return harita;
}

function ozetHaritasi(r: Rapor): Map<string, Record<string, string>> {
  const m = new Map<string, Record<string, string>>();
  for (const p of r.projects) m.set(projectName(p), p.fileDigests ?? {});
  return m;
}

export function computeDiff(beforeRaw: Rapor, afterRaw: Rapor): FarkSonucu {
  const onceki = duzlestir(beforeRaw);
  const sonraki = duzlestir(afterRaw);
  const oncekiOzet = ozetHaritasi(beforeRaw);
  const sonrakiOzet = ozetHaritasi(afterRaw);

  const yeni: FarkBulgusu[] = [];
  for (const [k, v] of sonraki) if (!onceki.has(k)) yeni.push(v);

  const vanished: Vanished[] = [];
  for (const [k, v] of onceki) {
    if (sonraki.has(k)) continue;
    const oldDigest = oncekiOzet.get(v.project)?.[v.file];
    const newDigest = sonrakiOzet.get(v.project)?.[v.file];
    let reason: DisappearanceReason;
    if (!oldDigest) {
      // Without a digest in the old report we cannot decide — assume the file changed.
      reason = "file-changed";
    } else if (newDigest === undefined) {
      // The new report has no digest for that file: either no findings remain in
      // it (digests are kept only for files with findings) or the file was deleted.
      // The digest cannot tell those apart; we do NOT claim "file missing", and we
      // do not put it in the suspicious bucket either — knowing what you do not
      reason = "file-changed";
    } else if (newDigest === oldDigest) {
      reason = "file-identical";
    } else {
      reason = "file-changed";
    }
    vanished.push({ ...v, reason });
  }

  return {
    yeni,
    vanished,
    suspicious: vanished.filter((k) => k.reason === "file-identical"),
  };
}

export function readReport(path: string): Rapor {
  return JSON.parse(readFileSync(path, "utf-8")) as Rapor;
}
