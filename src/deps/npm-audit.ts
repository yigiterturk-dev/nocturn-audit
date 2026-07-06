import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { DepsRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

const execFileAsync = promisify(execFile);

/**
 * A06 — Zafiyetli/eski bağımlılıklar.
 * `npm audit --json` sarmalayıcısı. Yıkıcı değil (yalnızca okuma).
 */

interface NpmAdvisory {
  name?: string;
  severity?: string;
  title?: string;
  url?: string;
  via?: Array<string | { title?: string; url?: string; severity?: string; source?: number }>;
  range?: string;
  fixAvailable?: boolean | { name?: string; version?: string };
}

const mapSeverity = (s: string | undefined): Severity => {
  switch ((s ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
};

export const npmAudit: DepsRule = {
  id: "a06-npm-audit",
  title: "Zafiyetli / güncelliğini yitirmiş bağımlılık",
  owasp: "A06:2021-Vulnerable & Outdated Components",
  severity: "high",
  kind: "deps",
  async run(ctx): Promise<Finding[]> {
    if (!ctx.exists("package.json")) return [];
    // lockfile yoksa npm audit anlamlı çalışmaz — bilgi ver
    const hasLock =
      ctx.exists("package-lock.json") ||
      ctx.exists("npm-shrinkwrap.json");

    let stdout = "";
    try {
      const res = await execFileAsync(
        "npm",
        ["audit", "--json", ...(hasLock ? [] : ["--package-lock-only"])],
        { cwd: ctx.root, maxBuffer: 20 * 1024 * 1024, timeout: 120_000 },
      );
      stdout = res.stdout;
    } catch (err: unknown) {
      // npm audit zafiyet bulunca non-zero exit döner ama stdout yine JSON'dur
      const e = err as { stdout?: string; message?: string };
      if (e.stdout) stdout = e.stdout;
      else {
        return [
          {
            ruleId: this.id,
            title: "npm audit çalıştırılamadı",
            owasp: this.owasp,
            severity: "info",
            description: `npm audit çalıştırılamadı: ${e.message ?? "bilinmeyen hata"}. Ağ erişimi veya lockfile gerekebilir.`,
            evidence: [fileEvidence("package.json", 1, "npm audit hatası")],
            remediation:
              "Proje dizininde `npm install` ile lockfile oluşturun ve `npm audit`i manuel çalıştırın.",
          },
        ];
      }
    }

    let parsed: {
      vulnerabilities?: Record<string, NpmAdvisory>;
      metadata?: { vulnerabilities?: Record<string, number> };
    };
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return [
        {
          ruleId: this.id,
          title: "npm audit çıktısı ayrıştırılamadı",
          owasp: this.owasp,
          severity: "info",
          description: "npm audit JSON çıktısı beklenmeyen formatta.",
          evidence: [fileEvidence("package.json", 1, "parse hatası")],
          remediation: "npm sürümünü güncelleyin ve `npm audit --json`i manuel deneyin.",
        },
      ];
    }

    const findings: Finding[] = [];
    const vulns = parsed.vulnerabilities ?? {};
    for (const [pkg, adv] of Object.entries(vulns)) {
      const severity = mapSeverity(adv.severity);
      // info seviyesindekileri atla (gürültü)
      if (severity === "info") continue;
      const viaTitles = (adv.via ?? [])
        .map((v) => (typeof v === "string" ? v : v.title))
        .filter(Boolean)
        .slice(0, 3)
        .join("; ");
      const fix =
        adv.fixAvailable === true
          ? "Düzeltme mevcut: `npm audit fix`."
          : adv.fixAvailable && typeof adv.fixAvailable === "object"
            ? `Düzeltme: ${adv.fixAvailable.name}@${adv.fixAvailable.version} (kırıcı olabilir).`
            : "Otomatik düzeltme yok — paketi manuel güncelleyin veya alternatif bulun.";

      findings.push({
        ruleId: this.id,
        title: `Zafiyetli paket: ${pkg} (${adv.severity})`,
        owasp: this.owasp,
        severity,
        description: `npm audit ${pkg} paketinde ${adv.severity} seviyesinde zafiyet bildirdi${
          viaTitles ? `: ${viaTitles}` : ""
        }. Etkilenen aralık: ${adv.range ?? "?"}.`,
        evidence: [
          fileEvidence("package.json", 1, `${pkg} — ${adv.severity} — ${adv.range ?? ""}`),
        ],
        remediation: fix,
      });
    }

    // özet bulgu yoksa ve metadata sağlıklıysa sessiz kal
    return findings;
  },
};
