import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, relative, sep } from "node:path";
import fg from "fast-glob";
import type { Finding } from "./finding.js";
import {
  emptyCounts,
  riskScore,
  type SeverityCounts,
} from "./severity.js";
import type {
  DepsContext,
  GrepMatch,
  LiveContext,
  ProbeResult,
  Project,
  Rule,
  StaticContext,
} from "./rule.js";

export interface ProjectReport {
  project: Project;
  findings: Finding[];
  counts: SeverityCounts;
  /**
   * Güven seviyesine göre bölünmüş severity sayımları (geriye-uyumlu ek alan).
   * `certain` = kesin bulgular, `heuristic` = olası (sezgisel) bulgular.
   * Toplamları `counts` ile birebir örtüşür.
   */
  certainCounts: SeverityCounts;
  heuristicCounts: SeverityCounts;
  score: number;
  /** Çalıştırılan kural kimlikleri. */
  rulesRun: string[];
  /** Atlanan sebep (varsa). */
  notes: string[];
}

export interface ScanOptions {
  /** Sadece statik kurallar. */
  staticOnly?: boolean;
  /** Sadece canlı kurallar. */
  liveOnly?: boolean;
  /** Deps kuralları çalışsın mı (varsayılan: staticOnly/liveOnly değilse evet). */
  includeDeps?: boolean;
}

const SOURCE_GLOBS = [
  "**/*.{ts,tsx,js,jsx,mjs,cjs}",
  "**/*.{json,env,mdx}",
  // SQL şemaları/migration'lar + Prisma şeması (RLS + şifresiz hassas veri kuralları için)
  "**/*.{sql,prisma}",
  // HTML dosyaları (SRI / harici script kuralı için)
  "**/*.{html,htm}",
  "next.config.{js,ts,mjs,cjs}",
  "vite.config.{js,ts}",
  ".env*",
  ".gitignore",
  "package.json",
];

const IGNORE_GLOBS = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/.git/**",
  "**/out/**",
  "**/report/**", // aracın kendi rapor çıktısı taranmasın
  "**/.vercel/**",
  "**/.turbo/**",
  "**/.cache/**",
];

/** Bir projenin kaynak dosyalarını topla (köke göre relatif). */
export async function collectFiles(root: string): Promise<string[]> {
  if (!existsSync(root)) return [];
  const files = await fg(SOURCE_GLOBS, {
    cwd: root,
    ignore: IGNORE_GLOBS,
    dot: true,
    onlyFiles: true,
    suppressErrors: true,
    followSymbolicLinks: false,
  });
  return files.map((f) => f.split("/").join(sep));
}

/**
 * git ls-files ile izlenen dosyaların posix-normalize edilmiş kümesini döner.
 * Git deposu değilse `null` döner (izleme bilgisi yok).
 */
export function collectTrackedFiles(root: string): Set<string> | null {
  try {
    const out = execFileSync("git", ["ls-files", "-z"], {
      cwd: root,
      timeout: 15_000,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    }).toString("utf8");
    const set = new Set<string>();
    for (const f of out.split("\0")) {
      const p = f.trim();
      if (p) set.add(p);
    }
    return set;
  } catch {
    return null;
  }
}

function buildStaticContext(
  project: Project,
  root: string,
  files: string[],
  tracked: Set<string> | null,
): StaticContext {
  const cache = new Map<string, string | null>();
  const read = (relPath: string): string | null => {
    if (cache.has(relPath)) return cache.get(relPath)!;
    const abs = join(root, relPath);
    let content: string | null = null;
    try {
      if (existsSync(abs)) content = readFileSync(abs, "utf8");
    } catch {
      content = null;
    }
    cache.set(relPath, content);
    return content;
  };

  const exists = (relPath: string): boolean => existsSync(join(root, relPath));

  const grep = (
    regex: RegExp,
    include?: (file: string) => boolean,
  ): GrepMatch[] => {
    const matches: GrepMatch[] = [];
    const flags = regex.flags.includes("g")
      ? regex.flags
      : regex.flags + "g";
    for (const file of files) {
      if (include && !include(file)) continue;
      const content = read(file);
      if (content == null) continue;
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const rx = new RegExp(regex.source, flags);
        let m: RegExpExecArray | null;
        while ((m = rx.exec(lines[i])) !== null) {
          matches.push({
            file,
            line: i + 1,
            column: m.index + 1,
            text: lines[i],
          });
          if (m.index === rx.lastIndex) rx.lastIndex++;
        }
      }
    }
    return matches;
  };

  const isTracked = (relPath: string): boolean => {
    if (!tracked) return false;
    return tracked.has(relPath.replace(/\\/g, "/"));
  };

  return {
    project,
    root,
    files,
    read,
    grep,
    exists,
    isTracked,
    isGitRepo: tracked !== null,
  };
}

function buildLiveContext(project: Project): LiveContext {
  const baseUrl = (project.url ?? "").replace(/\/$/, "");

  const probe = async (
    path: string,
    init?: RequestInit,
  ): Promise<ProbeResult> => {
    const url = path.startsWith("http")
      ? path
      : baseUrl + (path.startsWith("/") ? path : "/" + path);
    const method = (init?.method ?? "GET").toUpperCase();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12_000);
    try {
      const res = await fetch(url, {
        ...init,
        method,
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "user-agent": "nocturn-audit/0.1 (+detection-only)",
          ...(init?.headers ?? {}),
        },
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k] = v));
      let body = "";
      try {
        body = (await res.text()).slice(0, 2000);
      } catch {
        body = "";
      }
      const requestLine = `${method} ${url}`;
      const responseLine =
        `HTTP ${res.status} ${res.statusText}\n` +
        Object.entries(headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n");
      return {
        ok: true,
        url,
        method,
        status: res.status,
        statusText: res.statusText,
        headers,
        bodySnippet: body,
        requestLine,
        responseLine,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        url,
        method,
        status: 0,
        statusText: "",
        headers: {},
        bodySnippet: "",
        requestLine: `${method} ${url}`,
        responseLine: `ERROR: ${message}`,
        error: message,
      };
    } finally {
      clearTimeout(timer);
    }
  };

  return { project, baseUrl, probe };
}

function tallyCounts(findings: Finding[]): SeverityCounts {
  const counts = emptyCounts();
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** Bulguları güven seviyesine göre ikiye ayırıp severity sayımlarını üretir. */
function tallyByConfidence(findings: Finding[]): {
  certain: SeverityCounts;
  heuristic: SeverityCounts;
} {
  const certain = emptyCounts();
  const heuristic = emptyCounts();
  for (const f of findings) {
    if (f.confidence === "kesin") certain[f.severity]++;
    else heuristic[f.severity]++;
  }
  return { certain, heuristic };
}

/**
 * Tek projeyi tara. Kuralları kind'a göre uygun bağlamla çalıştırır.
 * Canlı kurallar YALNIZCA owned:true + url varsa çalışır.
 */
export async function scanProject(
  project: Project,
  rules: Rule[],
  options: ScanOptions = {},
): Promise<ProjectReport> {
  const notes: string[] = [];
  const findings: Finding[] = [];
  const rulesRun: string[] = [];
  const root = project.path;

  const runStatic = !options.liveOnly;
  const runLive = !options.staticOnly;
  // Deps (npm audit) ağ erişimi ister → yalnızca tam taramada, aksi belirtilmedikçe.
  const runDeps =
    options.includeDeps ?? (!options.liveOnly && !options.staticOnly);

  // --- Statik + deps için dosya toplama
  let files: string[] = [];
  if (runStatic || runDeps) {
    if (!existsSync(root)) {
      notes.push(`Proje yolu bulunamadı: ${root} — statik tarama atlandı.`);
    } else {
      files = await collectFiles(root);
    }
  }

  // --- Statik kurallar
  if (runStatic && existsSync(root)) {
    const tracked = collectTrackedFiles(root);
    const ctx = buildStaticContext(project, root, files, tracked);
    for (const rule of rules) {
      if (rule.kind !== "static") continue;
      try {
        const out = await rule.run(ctx);
        // Güven seviyesi: bulgu belirtmemişse kural varsayılanı, o da yoksa "olası".
        for (const f of out) {
          if (f.confidence === undefined) {
            f.confidence = rule.confidence ?? "olası";
          }
        }
        findings.push(...out);
        rulesRun.push(rule.id);
      } catch (err) {
        notes.push(
          `Kural ${rule.id} hata verdi: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }
  }

  // --- Deps kuralları
  if (runDeps && existsSync(root)) {
    const depsCtx: DepsContext = {
      project,
      root,
      exists: (rel: string) => existsSync(join(root, rel)),
    };
    for (const rule of rules) {
      if (rule.kind !== "deps") continue;
      try {
        const out = await rule.run(depsCtx);
        for (const f of out) {
          if (f.confidence === undefined) f.confidence = rule.confidence ?? "olası";
        }
        findings.push(...out);
        rulesRun.push(rule.id);
      } catch (err) {
        notes.push(
          `Deps kural ${rule.id} hata verdi: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }
  }

  // --- Canlı kurallar (yetki kapısı)
  if (runLive) {
    if (!project.owned) {
      notes.push(
        "Canlı test atlandı: proje owned:false (yetki yok — yalnızca sahip olunan hedefler test edilir).",
      );
    } else if (!project.url) {
      notes.push("Canlı test atlandı: url tanımlı değil.");
    } else {
      const ctx = buildLiveContext(project);
      for (const rule of rules) {
        if (rule.kind !== "live") continue;
        try {
          const out = await rule.run(ctx);
          for (const f of out) {
            if (f.confidence === undefined) f.confidence = rule.confidence ?? "olası";
          }
          findings.push(...out);
          rulesRun.push(rule.id);
        } catch (err) {
          notes.push(
            `Canlı kural ${rule.id} hata verdi: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
      }
    }
  }

  const counts = tallyCounts(findings);
  const { certain, heuristic } = tallyByConfidence(findings);
  return {
    project,
    findings,
    counts,
    certainCounts: certain,
    heuristicCounts: heuristic,
    score: riskScore(counts),
    rulesRun,
    notes,
  };
}

export function hasCritical(reports: ProjectReport[]): boolean {
  return reports.some((r) => r.counts.critical > 0);
}

export { relative };
