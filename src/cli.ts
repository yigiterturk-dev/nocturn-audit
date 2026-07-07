#!/usr/bin/env node
import { existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { loadRegistry, findProject } from "./registry.js";
import { scanProject, hasCritical, type ProjectReport } from "./core/engine.js";
import { allRules } from "./rules.js";
import { printReport } from "./report/terminal.js";
import { writeHtmlReport } from "./report/html.js";
import { writeJsonReport } from "./report/json.js";
import { SEVERITY_ORDER } from "./core/severity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
// dist/cli.js → proje kökü bir üst
const PROJECT_ROOT = resolve(__dirname, "..");

function targetsPath(custom?: string): string {
  if (custom) return resolve(custom);
  // önce cwd, sonra araç kökü
  const cwdT = resolve(process.cwd(), "targets.json");
  if (existsSync(cwdT)) return cwdT;
  return join(PROJECT_ROOT, "targets.json");
}

function dateStamp(): string {
  return new Date().toISOString().slice(0, 10);
}

const program = new Command();

program
  .name("nocturn-audit")
  .description(
    "OWASP Top 10 2021 tabanlı çok-projeli güvenlik denetim aracı (tespit + raporlama)",
  )
  .version("0.1.0");

program
  .command("scan")
  .description("Projeleri tara (statik + canlı + deps)")
  .argument("[project]", "yalnızca bu projeyi tara (isim)")
  .option("--static", "yalnızca statik kod taraması (canlıya dokunma)")
  .option("--live-only", "yalnızca canlı HTTP problar")
  .option("--no-deps", "npm audit adımını atla")
  .option("-t, --targets <path>", "targets.json yolu")
  .option("-v, --verbose", "tüm bulguları terminalde göster")
  .action(async (projectName, opts) => {
    const tPath = targetsPath(opts.targets);
    if (!existsSync(tPath)) {
      console.error(
        pc.red(`targets.json bulunamadı: ${tPath}\n`) +
          pc.dim("Örnek için targets.example.json'a bakın veya -t ile yol verin."),
      );
      process.exit(2);
    }

    let projects = loadRegistry(tPath);
    if (projects.length === 0) {
      console.error(pc.red("targets.json içinde proje yok."));
      process.exit(2);
    }

    if (projectName) {
      const p = findProject(projects, projectName);
      if (!p) {
        console.error(
          pc.red(`Proje bulunamadı: ${projectName}`) +
            pc.dim(`\nKayıtlı: ${projects.map((x) => x.name).join(", ")}`),
        );
        process.exit(2);
      }
      projects = [p];
    }

    const scanOpts = {
      staticOnly: opts.static === true,
      liveOnly: opts.liveOnly === true,
      includeDeps:
        opts.deps === false ? false : opts.static || opts.liveOnly ? false : true,
    };

    if (scanOpts.staticOnly && scanOpts.liveOnly) {
      console.error(pc.red("--static ve --live-only birlikte kullanılamaz."));
      process.exit(2);
    }

    console.log(
      pc.dim(
        `\nTaranıyor: ${projects.length} proje · mod: ${
          scanOpts.staticOnly ? "static" : scanOpts.liveOnly ? "live-only" : "full"
        }`,
      ),
    );

    const reports: ProjectReport[] = [];
    for (const project of projects) {
      process.stdout.write(pc.dim(`  → ${project.name} … `));
      const report = await scanProject(project, allRules, scanOpts);
      // bulguları severity'ye göre sırala
      report.findings.sort(
        (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
      );
      reports.push(report);
      console.log(
        pc.dim(
          `${report.findings.length} bulgu (${report.counts.critical}C/${report.counts.high}H · kesin ${report.certainCounts.critical}C/${report.certainCounts.high}H)`,
        ),
      );
    }

    printReport(reports, opts.verbose === true);

    // raporları yaz
    const stamp = dateStamp();
    const htmlPath = join(process.cwd(), "report", `${stamp}.html`);
    const jsonPath = join(process.cwd(), "report", `${stamp}.json`);
    writeHtmlReport(reports, htmlPath, stamp);
    writeJsonReport(reports, jsonPath);
    console.log(pc.dim(`  Rapor: ${htmlPath}`));
    console.log(pc.dim(`        ${jsonPath}\n`));

    if (hasCritical(reports)) {
      console.log(pc.red("  Kritik bulgu var → exit 1"));
      process.exit(1);
    }
    process.exit(0);
  });

program
  .command("list")
  .description("Kayıtlı projeleri göster")
  .option("-t, --targets <path>", "targets.json yolu")
  .action((opts) => {
    const tPath = targetsPath(opts.targets);
    if (!existsSync(tPath)) {
      console.error(pc.red(`targets.json bulunamadı: ${tPath}`));
      process.exit(2);
    }
    const projects = loadRegistry(tPath);
    console.log("");
    console.log(pc.bold(`  Kayıtlı projeler (${projects.length}) — ${tPath}`));
    console.log(pc.dim("  ───────────────────────────────────────────"));
    for (const p of projects) {
      const owned = p.owned ? pc.green("owned ") : pc.dim("static");
      const stack = [p.stack.framework, p.stack.db, p.stack.auth]
        .filter((x) => x && x !== "unknown")
        .join("/");
      const pathOk = existsSync(p.path) ? "" : pc.red(" [yol yok]");
      console.log(
        `  ${owned}  ${pc.bold(p.name.padEnd(18))} ${pc.dim(stack.padEnd(20))} ${
          p.url ? pc.cyan(p.url) : pc.dim("(url yok)")
        }${pathOk}`,
      );
    }
    console.log("");
  });

program
  .command("rules")
  .description("Aktif kural setini göster")
  .action(() => {
    console.log("");
    console.log(pc.bold(`  Aktif kurallar (${allRules.length})`));
    console.log(pc.dim("  ───────────────────────────────────────────"));
    const byOwasp = new Map<string, typeof allRules>();
    for (const r of allRules) {
      if (!byOwasp.has(r.owasp)) byOwasp.set(r.owasp, []);
      byOwasp.get(r.owasp)!.push(r);
    }
    const cats = [...byOwasp.keys()].sort();
    for (const cat of cats) {
      console.log("");
      console.log(pc.yellow(`  ${cat}`));
      for (const r of byOwasp.get(cat)!) {
        const kind =
          r.kind === "static"
            ? pc.blue("static")
            : r.kind === "live"
              ? pc.magenta("live  ")
              : pc.green("deps  ");
        const cwe = r.cwe ? pc.dim(` [${r.cwe}]`) : "";
        // Kural varsayılan güven seviyesi (bulgular bunu override edebilir).
        const conf =
          r.confidence === "kesin"
            ? pc.red("kesin")
            : pc.dim("olası");
        console.log(
          `    ${kind} ${conf} ${pc.dim(r.id.padEnd(34))} ${r.title}${cwe}`,
        );
      }
    }
    console.log("");
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(pc.red(`Hata: ${err instanceof Error ? err.message : String(err)}`));
  process.exit(2);
});
