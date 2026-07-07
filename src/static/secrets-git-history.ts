import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

const execFileAsync = promisify(execFile);

/**
 * A02 — Git geçmişine gömülü secret'lar.
 *
 * `git log -p` çıktısındaki EKLENEN satırları tarar: bilinen sağlayıcı anahtar
 * paternleri, yüksek-entropili sabit atamalar ve commit'lenmiş gerçek `.env` dosyaları.
 * Çalışma dizinindeki dosya temizlense bile sır geçmişte kalır — bu yüzden ayrı bir kural.
 */

interface Pattern {
  name: string;
  re: RegExp;
  severity: Severity;
}

const PROVIDER_PATTERNS: Pattern[] = [
  { name: "Stripe secret key", re: /sk_(live|test)_[A-Za-z0-9]{16,}/, severity: "critical" },
  { name: "Stripe restricted key", re: /rk_(live|test)_[A-Za-z0-9]{16,}/, severity: "high" },
  { name: "AWS access key", re: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "Google API key", re: /AIza[0-9A-Za-z_\-]{35}/, severity: "high" },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{36,}/, severity: "critical" },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/, severity: "high" },
  { name: "OpenAI key", re: /sk-(proj-)?[A-Za-z0-9]{20,}/, severity: "critical" },
  { name: "JWT/service token", re: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/, severity: "high" },
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, severity: "critical" },
];

// Hassas isimli değişkene atanan bir SABİT STRING LİTERAL'i (tırnak ZORUNLU).
// Tırnak zorunlu tutulduğu için `= decrypt(x)`, `= authHeader.slice(7)`,
// `= data.token`, `= process.env.X`, `= req.headers.get(...)` gibi ifade/çağrı/
// tanımlayıcı sağ-taraflar EŞLEŞMEZ — yalnızca gerçek gömülü literaller eşleşir.
const SECRET_ASSIGN =
  /\b(secret|api[_-]?key|apikey|password|passwd|token|private[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*["'`]([^"'`\n]{18,})["'`]/i;

const PLACEHOLDER =
  /(process\.env|import\.meta\.env|your[_-]?|xxx|placeholder|example|changeme|dummy|<[^>]+>|\$\{)/i;

// Gerçek anahtar ön-ekleri (sağlayıcı biçimleri + JWT + PEM).
const KEY_PREFIX = /^(sk[-_]|rk_|AKIA|AIza|gh[pousr]_|xox[baprs][-_]|eyJ|-----BEGIN)/;

/**
 * Bir string literal'in GERÇEK bir anahtar/parola biçiminde olup olmadığı.
 * Yalnızca: sağlayıcı ön-eki | JWT | PEM | uzun opak token/parola (anahtar karakter
 * seti + yüksek entropi + rakam VEYA karışık harf). Bu son koşul, `meta-app-secret-
 * cok-gizli` gibi sözlük-benzeri dummy'leri (tümü küçük harf, rakam yok) eler.
 */
function looksLikeRealKey(value: string): boolean {
  if (KEY_PREFIX.test(value)) return true;
  if (value.length < 18) return false;
  // Doğal dil / boşluk / cümle → gerçek sır değil.
  if (!/^[A-Za-z0-9._~+/=-]+$/.test(value)) return false;
  const hasDigit = /[0-9]/.test(value);
  const mixedCase = /[a-z]/.test(value) && /[A-Z]/.test(value);
  if (!hasDigit && !mixedCase) return false;
  return shannon(value) >= 3.6;
}

// Gerçek .env (.example/.sample/.template hariç)
const REAL_ENV_FILE = /(^|\/)\.env(\.[A-Za-z0-9_]+)?$/;
const ENV_EXAMPLE = /\.(example|sample|template|dist)$/;

// "Kod içinde gömülü sır" açısı için hariç tutulan dosyalar:
//  - test/fixture/mock dosyaları (dummy/fixture sırlar)
//  - dokümanlar (.md/.mdx/.txt/.rst — kod değil)
//  - lock dosyaları (pnpm-lock/package-lock/yarn.lock, *-lock.*)
const TEST_FILE =
  /(^|\/)(__tests__|__mocks__)\/|(^|\/)(fixtures?|mocks?)\/|\.(test|spec)\.[cm]?[jt]sx?$/i;
const DOC_FILE = /\.(md|mdx|txt|rst)$/i;
const LOCK_FILE =
  /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?)$|-lock\.[a-z0-9]+$/i;

/** Kod-gömülü sır taraması için dosya hariç tutuluyor mu (test/doc/lock). */
function isExcludedFile(file: string): boolean {
  const f = file.replace(/\\/g, "/");
  return TEST_FILE.test(f) || DOC_FILE.test(f) || LOCK_FILE.test(f);
}

function shannon(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let h = 0;
  for (const c in freq) {
    const p = freq[c] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export interface GitSecretHit {
  file: string;
  commit: string;
  name: string;
  severity: Severity;
  snippet: string;
}

/**
 * `git log -p` (veya benzeri unified diff) metnini tarar. Saf fonksiyon — test edilebilir.
 */
export function scanGitDiff(diff: string): GitSecretHit[] {
  const hits: GitSecretHit[] = [];
  const seen = new Set<string>();
  let commit = "";
  let file = "";
  const committedEnv = new Set<string>();

  for (const line of diff.split(/\r?\n/)) {
    const cm = /^commit\s+([0-9a-f]{7,40})/i.exec(line);
    if (cm) {
      commit = cm[1].slice(0, 10);
      continue;
    }
    const fm = /^\+\+\+ b\/(.+)$/.exec(line);
    if (fm) {
      file = fm[1].trim();
      // gerçek .env commit edilmiş mi?
      if (REAL_ENV_FILE.test(file) && !ENV_EXAMPLE.test(file)) {
        const key = `env:${file}`;
        if (!committedEnv.has(key)) {
          committedEnv.add(key);
          hits.push({
            file,
            commit,
            name: "Committed .env file",
            severity: "high",
            snippet: `${file} git geçmişine eklenmiş (.env commit'lenmiş)`,
          });
        }
      }
      continue;
    }
    // yalnızca eklenen satırlar (+ ile başlar, +++ değil)
    if (!line.startsWith("+") || line.startsWith("+++")) continue;
    // Test/doc/lock dosyaları "kod-gömülü sır" değildir → atla (commit'lenmiş .env
    // ayrımı yukarıda ayrıca yapılır ve bundan etkilenmez).
    if (file && isExcludedFile(file)) continue;
    const added = line.slice(1);

    for (const p of PROVIDER_PATTERNS) {
      const m = p.re.exec(added);
      if (m) {
        const key = `${commit}:${file}:${p.name}:${m[0].slice(0, 8)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        hits.push({
          file: file || "(bilinmeyen)",
          commit,
          name: p.name,
          severity: p.severity,
          snippet: added.replace(p.re, (x) => x.slice(0, 6) + "…redacted").trim().slice(0, 200),
        });
      }
    }

    const sm = SECRET_ASSIGN.exec(added);
    if (sm && !PLACEHOLDER.test(added)) {
      const value = sm[2];
      // Gerçek bir anahtar/parola BİÇİMİ olmalı (sağlayıcı ön-eki | JWT | PEM |
      // uzun opak yüksek-entropili token). Hash/UUID/kimlik/sözlük-dummy elenir.
      if (looksLikeRealKey(value)) {
        const key = `${commit}:${file}:entropy:${value.slice(0, 8)}`;
        if (!seen.has(key)) {
          seen.add(key);
          hits.push({
            file: file || "(bilinmeyen)",
            commit,
            name: "Yüksek-entropili sabit sır",
            severity: "high",
            snippet: added.replace(value, value.slice(0, 4) + "…redacted").trim().slice(0, 200),
          });
        }
      }
    }
  }
  return hits;
}

export const secretsGitHistory: StaticRule = {
  id: "a02-secrets-git-history",
  title: "Git geçmişine gömülü secret",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  cwe: "CWE-540",
  kind: "static",
  // Git geçmişinde fiilen bulunan sır → deterministik.
  confidence: "kesin",
  async run(ctx: StaticContext): Promise<Finding[]> {
    // Git deposu değilse sessizce atla.
    try {
      await execFileAsync("git", ["rev-parse", "--is-inside-work-tree"], {
        cwd: ctx.root,
        timeout: 10_000,
      });
    } catch {
      return [];
    }

    let stdout = "";
    try {
      const res = await execFileAsync(
        "git",
        ["log", "-p", "--all", "--no-color", "-n", "500"],
        { cwd: ctx.root, maxBuffer: 48 * 1024 * 1024, timeout: 120_000 },
      );
      stdout = res.stdout;
    } catch (err: unknown) {
      const e = err as { stdout?: string };
      if (e.stdout) stdout = e.stdout;
      else return [];
    }

    const hits = scanGitDiff(stdout);
    return hits.map((h) => ({
      ruleId: this.id,
      title: `${this.title} — ${h.name}`,
      owasp: this.owasp,
      severity: h.severity,
      cwe: this.cwe,
      description: `Git geçmişinde (commit ${h.commit || "?"}) ${h.name} tespit edildi. Dosya sonradan silinse/temizlense bile sır geçmişte kalır ve klonlayan herkes erişebilir.`,
      evidence: [fileEvidence(h.file, 1, `[commit ${h.commit || "?"}] ${h.snippet}`)],
      remediation:
        "Sızan anahtarı sağlayıcıda derhal iptal edip yenileyin. Geçmişten temizlemek için git filter-repo / BFG kullanın ve force-push edin; .env'i .gitignore'a ekleyin.",
      remediationCode:
        "git rm --cached .env && echo '.env' >> .gitignore\n" +
        "# Geçmişten silme (dikkat: geçmişi yeniden yazar):\n" +
        "git filter-repo --path .env --invert-paths",
    }));
  },
};
