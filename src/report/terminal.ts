import pc from "picocolors";
import type { ProjectReport } from "../core/engine.js";
import type { Finding } from "../core/finding.js";
import { SEVERITY_ORDER, type Severity } from "../core/severity.js";

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
  c === "kesin" ? pc.bold(pc.red("KESİN")) : pc.dim("olası");

export function printReport(reports: ProjectReport[], verbose = false): void {
  console.log("");
  console.log(pc.bold(pc.magenta("  nocturn-audit")) + pc.dim(" — güvenlik denetim özeti"));
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
      `${pc.red("kesin")} ${kc.critical}C/${kc.high}H · ` +
      `${pc.dim("olası")} ${hc.critical}C/${hc.high}H`;

    console.log("");
    console.log(
      `  ${pc.bold(r.project.name)}  ${countLabel(r)}  ${pc.dim(
        `skor:${r.score}`,
      )}  ${owned}${stack ? pc.dim(`  [${stack}]`) : ""}`,
    );
    console.log(pc.dim(`     güven: `) + confLabel);

    for (const note of r.notes) {
      console.log(pc.dim(`     · ${note}`));
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
      console.log(pc.dim(`     … +${findings.length - shown.length} bulgu daha (HTML raporda)`));
    }
    if (findings.length === 0) {
      console.log(pc.green("     ✓ bulgu yok"));
    }
  }

  console.log("");
  console.log(pc.dim("  ─────────────────────────────────────────────"));
  const verdict =
    certain.critical + certain.high > 0
      ? pc.bgRed(
          pc.white(
            ` ${certain.critical} KESİN KRİTİK · ${certain.high} KESİN YÜKSEK `,
          ),
        )
      : pc.green(" kesin kritik/yüksek bulgu yok ");
  console.log(
    `  KESİN:  ${pc.bold(pc.red(String(certain.critical)))} kritik  ` +
      `${pc.bold(pc.red(String(certain.high)))} yüksek  ` +
      `${pc.yellow(String(certain.medium))} orta`,
  );
  console.log(
    `  OLASI:  ${pc.dim(String(heuristic.critical))} kritik  ` +
      `${pc.dim(String(heuristic.high))} yüksek  ` +
      `${pc.dim(String(heuristic.medium))} orta  ${pc.dim(
        "(elle doğrulama gerektirir)",
      )}`,
  );
  console.log(
    `  Toplam risk skoru: ${pc.bold(String(totalScore))}   ${verdict}`,
  );
  console.log("");
}
