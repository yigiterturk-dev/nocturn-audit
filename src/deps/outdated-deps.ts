import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { DepsRule } from "../core/rule.js";

const execFileAsync = promisify(execFile);

/**
 * A06 — Eski / kullanımdan kaldırılmış (deprecated) bağımlılıklar.
 *
 * `a06-npm-audit` gerçek CVE zafiyetlerini kapsar; bu kural onu TAMAMLAR
 * (çakışmaz): birkaç MAJOR sürüm geride kalmış paketleri (sezgisel → olası)
 * ve bilinen deprecated paketleri işaretler. Zafiyet değil, bakım/operasyon
 * sağlığı sinyali olduğundan güven "olası", severity düşük tutulur.
 */

/** package.json'dan (root altında) deps + devDeps çıkar. */
function readDeps(root: string): {
  deps: Record<string, string>;
  raw: string | null;
} {
  try {
    const raw = readFileSync(join(root, "package.json"), "utf8");
    const pkg = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return {
      deps: { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) },
      raw,
    };
  } catch {
    return { deps: {}, raw: null };
  }
}

/** Sürüm dizesinden ilk major tam sayısını çek (^, ~, >= vb. temizlenir). */
function majorOf(v: string | undefined): number | null {
  if (!v) return null;
  const m = /(\d+)\./.exec(v) ?? /^\D*(\d+)\s*$/.exec(v);
  if (!m) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

/**
 * Bilinen deprecated / bakımsız paketler (çevrimdışı sezgisel).
 * Yalnızca yaygın ve net vakalar — FP taşkını yaratmamak için dar tutulur.
 */
const KNOWN_DEPRECATED: Record<string, string> = {
  request: "Artık bakımı yapılmıyor (deprecated). got/undici/native fetch kullanın.",
  "node-sass": "Deprecated — LibSass ölü. `sass` (Dart Sass) paketine geçin.",
  tslint: "Deprecated — ESLint + typescript-eslint'e geçin.",
  "@babel/polyfill": "Deprecated — core-js + regenerator-runtime doğrudan kullanın.",
  "left-pad": "Gereksiz mikro-paket — String.prototype.padStart kullanın.",
  "istanbul": "Deprecated — nyc / c8 kullanın.",
  "gulp-util": "Deprecated — ilgili küçük modülleri doğrudan kullanın.",
  "core-js@2": "core-js 2 bakımsız — core-js 3'e geçin.",
  "har-validator": "Deprecated bağımlılık.",
  "uuid@3": "uuid 3 eski — uuid 9+'a geçin.",
  "querystring": "Node çekirdek 'querystring' deprecated — URLSearchParams kullanın.",
  "moment": "Bakım modunda (maintenance) — day.js / date-fns / Temporal önerilir.",
  "@vercel/node-bridge": "Deprecated Vercel iç paketi.",
};

export interface OutdatedEntry {
  current?: string;
  wanted?: string;
  latest?: string;
}

/**
 * `npm outdated --json` çıktısını değerlendirir: >= 2 major geride kalanları döner.
 * Saf (ağsız) → birim testi için dışa açık.
 */
export function evaluateOutdated(
  parsed: Record<string, OutdatedEntry | OutdatedEntry[]>,
  deps: Record<string, string>,
): Array<{ pkg: string; behind: number; curMajor: number; latestMajor: number; entry: OutdatedEntry }> {
  const out: Array<{ pkg: string; behind: number; curMajor: number; latestMajor: number; entry: OutdatedEntry }> = [];
  for (const [pkg, val] of Object.entries(parsed)) {
    const entry = Array.isArray(val) ? val[0] : val;
    if (!entry) continue;
    const curMajor = majorOf(entry.current) ?? majorOf(deps[pkg]);
    const latestMajor = majorOf(entry.latest);
    if (curMajor == null || latestMajor == null) continue;
    const behind = latestMajor - curMajor;
    if (behind < 2) continue;
    out.push({ pkg, behind, curMajor, latestMajor, entry });
  }
  return out;
}

/** package.json'daki deps arasından bilinen deprecated paketleri döner. */
export function findDeprecated(
  deps: Record<string, string>,
): Array<{ name: string; note: string; version: string }> {
  const out: Array<{ name: string; note: string; version: string }> = [];
  for (const name of Object.keys(deps)) {
    const note = KNOWN_DEPRECATED[name];
    if (note) out.push({ name, note, version: deps[name] });
  }
  return out;
}

export const outdatedDeps: DepsRule = {
  id: "a06-outdated-deps",
  title: "Eski / deprecated bağımlılıklar",
  owasp: "A06:2021-Vulnerable & Outdated Components",
  severity: "medium",
  kind: "deps",
  confidence: "olası",
  async run(ctx): Promise<Finding[]> {
    if (!ctx.exists("package.json")) return [];
    const findings: Finding[] = [];
    const { deps } = readDeps(ctx.root);

    // --- 1) Bilinen deprecated paketler (çevrimdışı) ---
    for (const d of findDeprecated(deps)) {
      findings.push({
        ruleId: this.id,
        title: `Deprecated / bakımsız paket: ${d.name}`,
        owasp: this.owasp,
        severity: "low",
        confidence: "olası",
        cwe: "CWE-1104",
        description: `${d.name} kullanımdan kaldırılmış veya bakımı yapılmayan bir paket. ${d.note}`,
        evidence: [fileEvidence("package.json", 1, `${d.name}: ${d.version}`)],
        remediation: d.note,
      });
    }

    // --- 2) N major geride kalmış paketler (npm outdated --json) ---
    // node_modules yoksa `npm outdated` anlamlı çalışmaz (ve registry'ye gitmeye
    // çalışır) → atla. Yalnızca kurulu projelerde çalıştır.
    if (!ctx.exists("node_modules")) return findings;
    let stdout = "";
    try {
      const res = await execFileAsync("npm", ["outdated", "--json"], {
        cwd: ctx.root,
        maxBuffer: 20 * 1024 * 1024,
        timeout: 120_000,
      });
      stdout = res.stdout;
    } catch (err: unknown) {
      // npm outdated, güncelliğini yitirmiş paket bulunca non-zero exit döner ama
      // stdout yine JSON'dur.
      const e = err as { stdout?: string };
      if (e.stdout) stdout = e.stdout;
      else return findings; // ağ yok / çalıştırılamadı → yalnızca deprecated bulguları döner
    }

    if (!stdout.trim()) return findings;
    let parsed: Record<string, OutdatedEntry | OutdatedEntry[]>;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return findings;
    }

    for (const o of evaluateOutdated(parsed, deps)) {
      findings.push({
        ruleId: this.id,
        title: `Bağımlılık ${o.behind} major sürüm geride: ${o.pkg}`,
        owasp: this.owasp,
        severity: "medium",
        confidence: "olası",
        cwe: "CWE-1104",
        description: `${o.pkg} kurulu major sürümü ${o.curMajor}, en güncel ${o.latestMajor} (${o.behind} major geride). Eski major sürümler güvenlik yamalarını almayabilir; kırıcı değişiklikler biriktiği için yükseltme zorlaşır.`,
        evidence: [
          fileEvidence(
            "package.json",
            1,
            `${o.pkg}: kurulu ${o.entry.current ?? deps[o.pkg] ?? "?"} → latest ${o.entry.latest}`,
          ),
        ],
        remediation: `${o.pkg} paketini kademeli olarak güncelleyin (changelog + kırıcı değişikliklere dikkat). \`npm outdated ${o.pkg}\` ile durumu doğrulayın.`,
      });
    }

    return findings;
  },
};
