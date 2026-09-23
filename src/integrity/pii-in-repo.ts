import { execFileSync } from "node:child_process";
import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext } from "../core/rule.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — REAL PEOPLE's data committed to the repository.
 *
 * The most expensive mistake a data-collecting project can make, because it is
 * **irreversible**: deleting the file is not enough, it stays in git history;
 * once the repository is pushed it lives on someone else's disk. In one
 * harvesting project, the names and home addresses of 11,634 real people were
 * found committed exactly this way.
 *
 * Detection is cheap: reading the data file's HEADER row is enough. But two
 * conditions are required, or every `name` column would be a finding:
 *  1. The file is TRACKED by git (gitignored is fine),
 *  2. At least two DIFFERENT personal-data signals exist ("name" alone is not
 *     enough — a product has a name too; "name" + "address" is a person).
 *
 * And real rows are required: a template file that is nothing but a header is
 * not data.
 */

/**
 * Personal-data column families — matched by FRAGMENT.
 *
 * The first version matched the WHOLE column name (`^owner_name$`) and missed
 * the real data: field headers are compound —
 * `primary_owner_last_name`, `mailing_address_street`, `parcel_address_city`.
 * The fixtures passed while the real file slipped through. The same mistake,
 * twice, and both times only visible against real data.
 *
 * Now the column name is split into fragments (`_`, `-`, camelCase) and the
 * fragments are matched.
 */
const AILELER: Array<{ ad: string; esles: (part: string[]) => boolean }> = [
  // Turkish column names are recognised too.
  //
  // The first version knew only English headers and missed 9 of 12 data files in
  // a real repository — the largest being a list of 5,172 property owners with
  // Turkish headers. An audit tool that does not know its user's language makes
  // every file written in that language invisible.
  {
    ad: "isim",
    esles: (p) =>
      (p.includes("name") && p.some((x) => ["first", "last", "full", "owner", "person", "contact", "middle", "primary"].includes(x)))
      || p.some((x) => ["ad", "adi", "soyad", "soyadi", "isim", "malik", "sahip", "sahibi", "kisi", "musteri", "kiraci"].includes(x)),
  },
  {
    ad: "adres",
    esles: (p) => p.some((x) => ["address", "street", "mailing", "adres", "adresi", "sokak", "mahalle", "posta", "ilce", "sehir"].includes(x))
      || (p.includes("city") || p.includes("zip") || p.includes("postal")),
  },
  {
    ad: "telefon",
    esles: (p) => p.some((x) => ["phone", "mobile", "cell", "telefon", "gsm", "tel"].includes(x)),
  },
  {
    ad: "eposta",
    esles: (p) => p.some((x) => ["email", "mail", "eposta"].includes(x)),
  },
  {
    ad: "kimlik",
    esles: (p) => p.some((x) => ["ssn", "tckn", "passport", "dob", "birth", "dogum"].includes(x)),
  },
];

/** Splits a column name into fragments: `primary_owner_last_name` → [primary, owner, last, name] */
function parcala(kolon: string): string[] {
  return kolon
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((x) => x.toLowerCase())
    .filter(Boolean);
}

const DATA_FILE = /\.(csv|tsv|jsonl|ndjson)$/i;

/** Column names from the header row. */
function kolonlar(bas: string, ayirici: string): string[] {
  const firstLine = bas.split(/\r?\n/)[0] || "";
  return firstLine
    .split(ayirici)
    .map((k) => k.trim().replace(/^["']|["']$/g, ""))
    .filter(Boolean);
}

/** Keys of the first object, for JSONL. */
function jsonlAnahtarlari(bas: string): string[] {
  const firstLine = (bas.split(/\r?\n/).find((s) => s.trim().startsWith("{")) || "").trim();
  try {
    const nesne = JSON.parse(firstLine) as Record<string, unknown>;
    return Object.keys(nesne);
  } catch {
    // The line may be truncated; collect the keys roughly.
    return [...firstLine.matchAll(/"(\w+)"\s*:/g)].map((m) => m[1]);
  }
}

function sinyaller(headers: string[]): string[] {
  const bulunan = new Set<string>();
  for (const kolon of headers) {
    const part = parcala(kolon);
    for (const aile of AILELER) {
      if (aile.esles(part)) bulunan.add(aile.ad);
    }
  }
  return [...bulunan];
}

export const piiInRepo: StaticRule = {
  id: "a02-pii-in-repo",
  title: "Real people's data committed to the repository",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  kind: "static",
  // Without git history and tracking information this rule can measure NOTHING.
  // Returning `[]` outside a repository would read as "clean" — but nothing was looked at.
  requires: ["git"],
  confidence: "certain",
  cwe: "CWE-359",
  run(ctx: StaticContext): Finding[] {
    // Without git information the "is it tracked" question cannot be answered, so
    // we stay silent. Reporting nothing beats reporting with false certainty.
    if (!ctx.isGitRepo) return [];

    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!DATA_FILE.test(file)) continue;
      if (!ctx.isTracked(file)) continue;

      const bas = ctx.readHead(file, 32 * 1024);
      if (!bas) continue;

      const jsonl = /\.(jsonl|ndjson)$/i.test(file);
      const headers = jsonl
        ? jsonlAnahtarlari(bas)
        : kolonlar(bas, file.toLowerCase().endsWith(".tsv") ? "\t" : ",");
      if (!headers.length) continue;

      const bulunan = sinyaller(headers);
      // Two DIFFERENT families are required: "name" alone can be a product name,
      // "name" + "address" is a person.
      if (bulunan.length < 2) continue;

      // Real data rather than a template? There must be rows after the header.
      const lines = bas.split(/\r?\n/).filter((s) => s.trim().length > 0);
      const veriSatiri = jsonl ? lines.length : lines.length - 1;
      if (veriSatiri < 1) continue;

      findings.push({
        ruleId: "a02-pii-in-repo",
        title: "Real people's data committed to the repository",
        owasp: "A02:2021-Cryptographic Failures",
        severity: "high",
        confidence: "certain",
        cwe: "CWE-359",
        description:
          `\`${file}\` is tracked by git and carries personal-data columns ` +
          `(${bulunan.join(" + ")}). This mistake is IRREVERSIBLE: deleting the file is not enough, ` +
          "it stays in git history — and once the repository has been pushed, it is on someone else's disk.",
        evidence: [fileEvidence(file, 1, headers.slice(0, 8).join(", "))],
        remediation:
          "Add the file to `.gitignore` and untrack it with `git rm --cached`. If the repository has NOT " +
          "BEEN PUSHED yet, purge the history too (git filter-repo). If it has, treat the data as " +
          "breached: you now have obligations towards the people involved (GDPR/KVKK). " +
          "Keep the data in access-restricted storage, not in the repository.",
      });
    }
    // HISTORY. Untracking is not enough.
    //
    // This is the truly irreversible part: once the file is untracked with
    // `git rm --cached` and added to `.gitignore`, today's scan comes back CLEAN
    // while the data sits in commit history, one `push` away. An audit ran into
    // exactly this: the files had been fixed, the history had not, and the rule
    // stayed silent.
    findings.push(...gecmisteKalanlar(ctx, new Set(findings.map((f) => f.evidence[0]?.file))));
    return findings;
  },
};

/** Data files that were once added but are no longer tracked. */
function gecmisteKalanlar(ctx: StaticContext, zatenBildirilen: Set<string | undefined>): Finding[] {
  let eklenenler: string[];
  try {
    const cikti = execFileSync(
      "git",
      ["log", "--all", "--diff-filter=A", "--name-only", "--format="],
      { cwd: ctx.root, encoding: "utf8", timeout: 60_000, maxBuffer: 32 * 1024 * 1024,
        stdio: ["ignore", "pipe", "ignore"] },
    );
    eklenenler = [...new Set(cikti.split("\n").map((x) => x.trim()).filter(Boolean))];
  } catch {
    return [];
  }

  const findings: Finding[] = [];
  const adaylar = eklenenler
    .filter((f) => DATA_FILE.test(f))
    .filter((f) => !ctx.isTracked(f) && !zatenBildirilen.has(f))
    .slice(0, 40); // keep the cost of scanning history bounded

  for (const file of adaylar) {
    let bas: string;
    try {
      // We need the commit that ADDED the file. Taking the most recent commit
      // with `-1` was wrong: that is usually the commit that DELETED it, where
      // the file does not exist — git failed with "exists on disk, but not in <rev>".
      const rev = execFileSync(
        "git",
        ["log", "--all", "--diff-filter=A", "--format=%H", "-1", "--", file],
        { cwd: ctx.root, encoding: "utf8", timeout: 20_000, stdio: ["ignore", "pipe", "ignore"] },
      ).trim();
      if (!rev) continue;
      bas = execFileSync("git", ["show", `${rev}:${file}`],
        { cwd: ctx.root, encoding: "utf8", timeout: 20_000, maxBuffer: 4 * 1024 * 1024,
          stdio: ["ignore", "pipe", "ignore"] }).slice(0, 32 * 1024);
    } catch {
      continue;
    }

    const jsonl = /\.(jsonl|ndjson)$/i.test(file);
    const headers = jsonl
      ? jsonlAnahtarlari(bas)
      : kolonlar(bas, file.toLowerCase().endsWith(".tsv") ? "\t" : ",");
    const bulunan = sinyaller(headers);
    if (bulunan.length < 2) continue;

    findings.push({
      ruleId: "a02-pii-in-repo",
      title: "Personal data still sits in git HISTORY (the file was untracked)",
      owasp: "A02:2021-Cryptographic Failures",
      severity: "high",
      confidence: "certain",
      cwe: "CWE-359",
      description:
        `\`${file}\` is no longer tracked but remains in commit history, carrying personal-data ` +
        `columns (${bulunan.join(" + ")}). Untracking cleans today's scan, not the data — ` +
        "it is still one `push` away.",
      evidence: [fileEvidence(file, 1, headers.slice(0, 8).join(", "))],
      remediation:
        "If the repository has NOT BEEN PUSHED, purge the history: `git filter-repo --path <file> --invert-paths`. " +
        "⚠ `--invert-paths` deletes EVERYTHING on the list — never list a file you want to keep, " +
        "or you lose it too. Take a backup first: `git bundle create ../backup.bundle --all`. " +
        "Then push. If it HAS been pushed, treat the data as breached: purging history does not recall " +
        "remote copies or existing clones.",
    });
  }
  return findings;
}
