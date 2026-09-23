import pc from "picocolors";
import { userLang } from "../core/lang.js";
import type { ProjectReport } from "../core/engine.js";
import type { Finding } from "../core/finding.js";
import { SEVERITY_ORDER, type Severity } from "../core/severity.js";
import type { StandardsCheckResult, StandardsResult } from "../standards/types.js";

const sevColor = (s: Severity, text: string): string => {
  switch (s) {
    case "critical":
      return pc.bgRed(pc.white(` ${text} `));
    case "high":
      return pc.red(text);
    case "medium":
      return pc.yellow(text);
    case "low":
      return pc.cyan(text);
    case "info":
      return pc.dim(text);
  }
};

const countLabel = (r: ProjectReport): string => {
  const c = r.counts;
  const parts = [
    c.critical ? pc.bgRed(pc.white(` C:${c.critical} `)) : pc.dim("C:0"),
    c.high ? pc.red(`H:${c.high}`) : pc.dim("H:0"),
    c.medium ? pc.yellow(`M:${c.medium}`) : pc.dim("M:0"),
    c.low ? pc.cyan(`L:${c.low}`) : pc.dim("L:0"),
    c.info ? pc.dim(`I:${c.info}`) : pc.dim("I:0"),
  ];
  return parts.join(" ");
};

const confTag = (c: Finding["confidence"]): string =>
  c === "certain" ? pc.bold(pc.red("CERTAIN")) : pc.dim("likely");

export function printReport(reports: ProjectReport[], verbose = false): void {
  console.log("");
  console.log(pc.bold(pc.magenta("  nocturn-audit")) + pc.dim(" — security audit summary"));
  console.log(pc.dim("  ─────────────────────────────────────────────"));

  let totalCritical = 0;
  let totalScore = 0;
  const certain = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const heuristic = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const r of reports) {
    totalCritical += r.counts.critical;
    totalScore += r.score;
    for (const k of ["critical", "high", "medium", "low", "info"] as const) {
      certain[k] += r.certainCounts[k];
      heuristic[k] += r.heuristicCounts[k];
    }

    const owned = r.project.owned ? pc.green("owned") : pc.dim("static-only");
    const stack = [
      r.project.stack.framework,
      r.project.stack.db,
      r.project.stack.auth,
    ]
      .filter((x) => x && x !== "unknown")
      .join("/");

    const kc = r.certainCounts;
    const hc = r.heuristicCounts;
    const confLabel =
      `${pc.red("certain")} ${kc.critical}C/${kc.high}H · ` +
      `${pc.dim("likely")} ${hc.critical}C/${hc.high}H`;

    console.log("");
    // PİSLİK ETİKETİ — ham score'un yanında karşılaştırılabilir 0-100.
    // Kısmi ölçümde alt sınır olduğu BELLİ edilir; 0 asla "temiz" sayılmaz.
    const pislikLabel = r.pislik.partial
      ? pc.yellow(`${r.pislik.score}/100 ${r.pislik.label}`)
      : r.pislik.score === 0
        ? pc.green(`${r.pislik.score}/100 ${r.pislik.label}`)
        : r.pislik.score >= 30
          ? pc.red(`${r.pislik.score}/100 ${r.pislik.label}`)
          : pc.yellow(`${r.pislik.score}/100 ${r.pislik.label}`);
    const gapNote = r.pislik.partial
      ? pc.dim(
          userLang() === "tr"
            ? `  (kısmi ölçüm — ${r.gaps.length} kural ölçülemedi, gerçek pislik ≥ bu)`
            : `  (partial measurement — ${r.gaps.length} rule(s) could not run; true dirtiness ≥ this)`,
        )
      : "";

    console.log(
      `  ${pc.bold(r.project.name)}  ${countLabel(r)}  ${pc.dim(
        `score:${r.score}`,
      )}  ${pislikLabel}${gapNote}  ${owned}${stack ? pc.dim(`  [${stack}]`) : ""}`,
    );
    console.log(pc.dim(`     confidence: `) + confLabel);

    for (const note of r.notes) {
      console.log(pc.dim(`     · ${note}`));
    }

    // WHAT COULD NOT BE MEASURED. "No findings" and "could not look" must not
    // share the same silence on the same screen — that was this tool's most
    if (r.gaps.length) {
      const grup = new Map<string, string[]>();
      for (const b of r.gaps) {
        const liste = grup.get(b.reason) ?? [];
        liste.push(b.ruleId);
        grup.set(b.reason, liste);
      }
      for (const [reason, rules] of grup) {
        console.log(
          pc.yellow(`     ⃠ not measured (${rules.length} rule(s)): ${reason}`) +
            pc.dim(` — ${rules.join(", ")}`),
        );
      }
    }

    const findings = [...r.findings].sort(
      (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
    );
    const shown = verbose ? findings : findings.slice(0, 8);
    for (const f of shown) {
      const ev = f.evidence[0];
      const loc =
        ev?.kind === "file"
          ? pc.dim(` (${ev.file}:${ev.line})`)
          : ev?.kind === "http"
            ? pc.dim(` (${ev.request?.slice(0, 48)})`)
            : "";
      console.log(
        `     ${sevColor(f.severity, f.severity.toUpperCase().padEnd(8))} ${confTag(
          f.confidence,
        )} ${f.title}${loc}`,
      );
    }
    if (!verbose && findings.length > shown.length) {
      console.log(pc.dim(`     … +${findings.length - shown.length} more finding(s) (see the HTML report)`));
    }
    if (findings.length === 0) {
      console.log(pc.green("     ✓ no findings"));
    }

    // Standards profile summary (security + performance checklist)
    if (r.standards) {
      const s = r.standards;
      const scoreCol =
        s.score >= 80 ? pc.green : s.score >= 60 ? pc.yellow : pc.red;
      console.log(
        pc.dim("     standards: ") +
          scoreCol(`score ${s.score}`) +
          pc.dim(
            ` (security ${s.categories.security.score} · performance ${s.categories.performance.score})  ` +
              `${s.counts.pass} pass · `,
          ) +
          (s.counts.open ? pc.red(`${s.counts.open} open`) : pc.dim("0 open")) +
          pc.dim(` · ${s.counts.manual} manual · ${s.counts.na} n/a`),
      );
    }
  }

  console.log("");
  console.log(pc.dim("  ─────────────────────────────────────────────"));
  const verdict =
    certain.critical + certain.high > 0
      ? pc.bgRed(
          pc.white(
            ` ${certain.critical} CERTAIN CRITICAL · ${certain.high} CERTAIN HIGH `,
          ),
        )
      : pc.green(" no certain critical/high findings ");
  console.log(
    `  CERTAIN: ${pc.bold(pc.red(String(certain.critical)))} critical  ` +
      `${pc.bold(pc.red(String(certain.high)))} high  ` +
      `${pc.yellow(String(certain.medium))} medium`,
  );
  console.log(
    `  LIKELY:  ${pc.dim(String(heuristic.critical))} critical  ` +
      `${pc.dim(String(heuristic.high))} high  ` +
      `${pc.dim(String(heuristic.medium))} medium  ${pc.dim(
        "(needs manual verification)",
      )}`,
  );
  console.log(
    `  Total risk score: ${pc.bold(String(totalScore))}   ${verdict}`,
  );

  // COVERAGE WARNING — "no findings" and "could not look" are not the same thing.
  //
  // Scanning a Python project, the tool could read none of its 20 source files,
  // looked only at SQL, and finished with "no certain critical/high findings".
  // Giving confidence about a project it could not read is the very mistake this
  // tool exists to chase. With low coverage a green verdict is meaningless, and it says so.
  for (const rapor of reports) {
    const k = rapor.coverage;
    if (!k || !k.okunamayan) continue;
    const diller = k.diller.map((d) => `${d.dil} ${d.count}`).join(", ");
    const line =
      `  ⚠ ${rapor.project.name}: ${k.yuzde}% of source files were read — ` +
      `${k.okunamayan} file(s) UNSUPPORTED (${diller}).`;
    console.log(k.yuzde < 50 ? pc.bgYellow(pc.black(line)) : pc.yellow(line));
    if (k.yuzde < 50) {
      console.log(
        pc.yellow(
          "    Here \"no findings\" means \"could not look\"; the verdict above does NOT cover those languages.",
        ),
      );
    }
  }
  console.log("");
}

// ---- Standards profile detail output (the standards command) ----

const statusTag = (c: StandardsCheckResult): string => {
  switch (c.status) {
    case "pass":
      return pc.green("✓ PASS   ");
    case "open":
      return c.level === "critical"
        ? pc.bgRed(pc.white(" ✗ KALDI "))
        : pc.red("✗ KALDI  ");
    case "manual":
      return pc.yellow("? MANUEL ");
    case "na":
      return pc.dim("- N/A    ");
  }
};

const levelTag = (l: StandardsCheckResult["level"]): string =>
  l === "critical" ? pc.red("critical") : l === "warning" ? pc.yellow("warning ") : pc.dim("info    ");

export function printStandards(projectName: string, s: StandardsResult): void {
  console.log("");
  console.log(
    pc.bold(pc.magenta("  nocturn-audit")) +
      pc.dim(" — standards profile · ") +
      pc.bold(projectName),
  );
  console.log(pc.dim("  ─────────────────────────────────────────────"));
  const scoreCol = s.score >= 80 ? pc.green : s.score >= 60 ? pc.yellow : pc.red;
  console.log(
    `  Skor: ${scoreCol(pc.bold(String(s.score)))}   ` +
      pc.dim(`security ${s.categories.security.score} · performance ${s.categories.performance.score}   `) +
      pc.dim(
        `${s.counts.pass} pass · ${s.counts.open} open · ${s.counts.manual} manual · ${s.counts.na} n/a`,
      ),
  );
  for (const cat of ["security", "performance", "integrity"] as const) {
    console.log("");
    console.log(pc.yellow(cat === "security" ? "  SECURITY" : cat === "performance" ? "  PERFORMANCE" : "  INTEGRITY"));
    for (const c of s.checks.filter((x) => x.category === cat)) {
      console.log(`   ${statusTag(c)} ${levelTag(c.level)} ${pc.bold(c.title)} ${pc.dim(`(${c.id})`)}`);
      console.log(pc.dim(`            ${c.detail}`));
      if (c.status === "open" || c.status === "manual") {
        const ev = c.evidence[0];
        if (ev?.kind === "file" && ev.file) {
          console.log(pc.dim(`            evidence: ${ev.file}:${ev.line ?? 1}${ev.snippet ? ` → ${ev.snippet}` : ""}`));
        }
        console.log(pc.cyan(`            fix: `) + pc.dim(c.remediation));
      }
    }
  }
  console.log("");
}
