import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { ProjectReport } from "../core/engine.js";
import type { Finding, OwaspCategory } from "../core/finding.js";
import { SEVERITY_ORDER, type Severity } from "../core/severity.js";

const esc = (s: string): string =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

const SEV_COLOR: Record<Severity, string> = {
  critical: "#b91c1c",
  high: "#dc2626",
  medium: "#d97706",
  low: "#0891b2",
  info: "#6b7280",
};

const OWASP_ORDER: OwaspCategory[] = [
  "A01:2021-Broken Access Control",
  "A02:2021-Cryptographic Failures",
  "A03:2021-Injection",
  "A04:2021-Insecure Design",
  "A05:2021-Security Misconfiguration",
  "A06:2021-Vulnerable & Outdated Components",
  "A07:2021-Identification & Authentication Failures",
  "A08:2021-Software & Data Integrity Failures",
  "A09:2021-Security Logging & Monitoring Failures",
  "A10:2021-Server-Side Request Forgery",
];

function evidenceHtml(f: Finding): string {
  return f.evidence
    .map((e) => {
      if (e.kind === "file") {
        return `<div class="ev"><span class="evloc">${esc(e.file ?? "")}:${e.line ?? ""}</span><pre>${esc(e.snippet ?? "")}</pre></div>`;
      }
      return `<div class="ev"><span class="evloc">HTTP</span><pre>${esc(e.request ?? "")}\n\n${esc(e.response ?? "")}</pre></div>`;
    })
    .join("");
}

function findingHtml(f: Finding): string {
  const conf = f.confidence ?? "olası";
  const confBadge = `<span class="confbadge ${conf === "kesin" ? "kesin" : "olasi"}">${
    conf === "kesin" ? "KESİN" : "OLASI"
  }</span>`;
  return `<div class="finding" data-sev="${f.severity}" data-conf="${conf}">
    <div class="fhead">
      <span class="badge" style="background:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span>
      ${confBadge}
      <span class="ftitle">${esc(f.title)}</span>
      <span class="ruleid">${esc(f.ruleId)}</span>
    </div>
    <p class="fdesc">${esc(f.description)}</p>
    ${evidenceHtml(f)}
    <div class="fix"><strong>Düzeltme:</strong> ${esc(f.remediation)}</div>
  </div>`;
}

function projectHtml(r: ProjectReport): string {
  const byCat = new Map<OwaspCategory, Finding[]>();
  for (const f of r.findings) {
    if (!byCat.has(f.owasp)) byCat.set(f.owasp, []);
    byCat.get(f.owasp)!.push(f);
  }

  const catSections = OWASP_ORDER.filter((c) => byCat.has(c))
    .map((cat) => {
      const items = byCat
        .get(cat)!
        .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
      return `<section class="cat"><h3>${esc(cat)} <span class="catcount">${items.length}</span></h3>${items
        .map(findingHtml)
        .join("")}</section>`;
    })
    .join("");

  const c = r.counts;
  const chips = `
    <span class="chip crit">${c.critical} kritik</span>
    <span class="chip high">${c.high} yüksek</span>
    <span class="chip med">${c.medium} orta</span>
    <span class="chip low">${c.low} düşük</span>
    <span class="chip info">${c.info} bilgi</span>`;

  const notes = r.notes.length
    ? `<ul class="notes">${r.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>`
    : "";

  const stack = [r.project.stack.framework, r.project.stack.db, r.project.stack.auth]
    .filter((x) => x && x !== "unknown")
    .join(" · ");

  return `<article class="project">
    <header class="phead">
      <h2>${esc(r.project.name)}</h2>
      <div class="pmeta">
        ${r.project.url ? `<a href="${esc(r.project.url)}">${esc(r.project.url)}</a>` : ""}
        <span class="tag ${r.project.owned ? "owned" : "notowned"}">${r.project.owned ? "owned (canlı test)" : "static-only"}</span>
        ${stack ? `<span class="tag">${esc(stack)}</span>` : ""}
        <span class="tag">skor ${r.score}</span>
      </div>
      <div class="chips">${chips}</div>
      ${notes}
    </header>
    ${catSections || '<p class="clean">✓ Bu projede bulgu yok.</p>'}
  </article>`;
}

export function buildHtml(reports: ProjectReport[], dateLabel: string): string {
  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0, score: 0 };
  const certain = { critical: 0, high: 0, medium: 0 };
  const heuristic = { critical: 0, high: 0, medium: 0 };
  for (const r of reports) {
    totals.critical += r.counts.critical;
    totals.high += r.counts.high;
    totals.medium += r.counts.medium;
    totals.low += r.counts.low;
    totals.info += r.counts.info;
    totals.score += r.score;
    certain.critical += r.certainCounts.critical;
    certain.high += r.certainCounts.high;
    certain.medium += r.certainCounts.medium;
    heuristic.critical += r.heuristicCounts.critical;
    heuristic.high += r.heuristicCounts.high;
    heuristic.medium += r.heuristicCounts.medium;
  }

  const projects = reports
    .sort((a, b) => b.score - a.score)
    .map(projectHtml)
    .join("");

  return `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>nocturn-audit — ${esc(dateLabel)}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #0b0b10; color: #e6e6ea; line-height: 1.5; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 2rem 1.25rem 5rem; }
  h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
  .sub { color: #9aa; margin: 0 0 1.5rem; font-size: .9rem; }
  .summary { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 2rem; }
  .stat { background: #16161f; border: 1px solid #26263a; border-radius: 10px; padding: .6rem 1rem; min-width: 90px; }
  .stat .n { font-size: 1.4rem; font-weight: 700; }
  .stat .l { font-size: .72rem; color: #99a; text-transform: uppercase; letter-spacing: .04em; }
  .stat.crit .n { color: #f87171; } .stat.high .n { color: #fb7185; }
  .stat.med .n { color: #fbbf24; } .stat.low .n { color: #22d3ee; }
  .project { background: #12121a; border: 1px solid #23233400; border-top: 1px solid #26263a; border-radius: 14px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 0 #000; }
  .phead h2 { margin: 0 0 .4rem; font-size: 1.25rem; }
  .pmeta { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-bottom: .6rem; font-size: .82rem; }
  .pmeta a { color: #7dd3fc; text-decoration: none; }
  .tag { background: #22223200; border: 1px solid #33334a; padding: .1rem .5rem; border-radius: 999px; color: #aab; }
  .tag.owned { border-color: #16a34a; color: #4ade80; }
  .tag.notowned { color: #889; }
  .chips { display: flex; flex-wrap: wrap; gap: .4rem; margin-bottom: .5rem; }
  .chip { font-size: .74rem; padding: .12rem .5rem; border-radius: 6px; background: #1c1c28; color: #99a; }
  .chip.crit { background: #3b0d0d; color: #fca5a5; } .chip.high { background: #3b1114; color: #fda4af; }
  .chip.med { background: #3a2a08; color: #fcd34d; } .chip.low { background: #06303a; color: #67e8f9; }
  .notes { font-size: .8rem; color: #99a; margin: .4rem 0 0; padding-left: 1.1rem; }
  .cat { margin-top: 1.1rem; }
  .cat h3 { font-size: .95rem; color: #cdd; border-bottom: 1px solid #26263a; padding-bottom: .3rem; margin: 0 0 .6rem; }
  .catcount { color: #778; font-weight: 400; font-size: .8rem; }
  .finding { border: 1px solid #26263a; border-left: 3px solid #555; border-radius: 8px; padding: .7rem .9rem; margin-bottom: .7rem; background: #14141d; }
  .finding[data-sev="critical"] { border-left-color: #b91c1c; }
  .finding[data-sev="high"] { border-left-color: #dc2626; }
  .finding[data-sev="medium"] { border-left-color: #d97706; }
  .finding[data-sev="low"] { border-left-color: #0891b2; }
  .fhead { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-bottom: .35rem; }
  .badge { color: #fff; font-size: .68rem; font-weight: 700; padding: .1rem .45rem; border-radius: 5px; letter-spacing: .03em; }
  .confbadge { font-size: .62rem; font-weight: 700; padding: .1rem .4rem; border-radius: 5px; letter-spacing: .04em; border: 1px solid transparent; }
  .confbadge.kesin { background: #3b0d0d; color: #fca5a5; border-color: #7f1d1d; }
  .confbadge.olasi { background: #1c1c28; color: #99a; border-color: #33334a; }
  .stat.kesin .n { color: #f87171; } .stat.olasi .n { color: #9aa; }
  .confsummary { margin-top: -1rem; }
  .conflegend { font-size: .78rem; color: #99a; margin: -1rem 0 2rem; }
  .ftitle { font-weight: 600; font-size: .92rem; }
  .ruleid { margin-left: auto; font-size: .7rem; color: #667; font-family: ui-monospace, monospace; }
  .fdesc { margin: .2rem 0 .5rem; font-size: .85rem; color: #bcc; }
  .ev { margin: .3rem 0; }
  .evloc { font-size: .7rem; color: #7aa; font-family: ui-monospace, monospace; }
  .ev pre { margin: .15rem 0 0; background: #0a0a0f; border: 1px solid #222; border-radius: 6px; padding: .5rem .6rem; overflow-x: auto; font-size: .78rem; color: #cdd; white-space: pre-wrap; word-break: break-word; }
  .fix { margin-top: .5rem; font-size: .82rem; color: #9c9; background: #0e1a0e; border: 1px solid #1e3a1e; border-radius: 6px; padding: .4rem .6rem; }
  .clean { color: #4ade80; }
  footer { color: #667; font-size: .75rem; margin-top: 2rem; text-align: center; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>nocturn-audit</h1>
    <p class="sub">OWASP Top 10 (2021) güvenlik denetim raporu · ${esc(dateLabel)} · ${reports.length} proje · yalnızca tespit + raporlama</p>
    <div class="summary">
      <div class="stat crit"><div class="n">${totals.critical}</div><div class="l">Kritik</div></div>
      <div class="stat high"><div class="n">${totals.high}</div><div class="l">Yüksek</div></div>
      <div class="stat med"><div class="n">${totals.medium}</div><div class="l">Orta</div></div>
      <div class="stat low"><div class="n">${totals.low}</div><div class="l">Düşük</div></div>
      <div class="stat"><div class="n">${totals.info}</div><div class="l">Bilgi</div></div>
      <div class="stat"><div class="n">${totals.score}</div><div class="l">Risk skoru</div></div>
    </div>
    <div class="summary confsummary">
      <div class="stat kesin"><div class="n">${certain.critical + certain.high}</div><div class="l">KESİN kritik+yüksek</div></div>
      <div class="stat kesin"><div class="n">${certain.medium}</div><div class="l">KESİN orta</div></div>
      <div class="stat olasi"><div class="n">${heuristic.critical + heuristic.high}</div><div class="l">OLASI kritik+yüksek</div></div>
      <div class="stat olasi"><div class="n">${heuristic.medium}</div><div class="l">OLASI orta</div></div>
    </div>
    <p class="conflegend">Kırmızı sayılar <strong>KESİN</strong> (deterministik) bulgulardır; <em>OLASI</em> bulgular sezgiseldir ve elle doğrulama gerektirir.</p>
    ${projects}
    <footer>nocturn-audit · detection-only · exploit/DoS yok · canlı test yalnızca owned:true hedeflerde</footer>
  </div>
</body>
</html>`;
}

export function writeHtmlReport(
  reports: ProjectReport[],
  outPath: string,
  dateLabel: string,
): void {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, buildHtml(reports, dateLabel), "utf8");
}
