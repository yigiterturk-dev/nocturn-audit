import { readdirSync, statSync } from "node:fs";
import { join, relative, extname } from "node:path";

/**
 * COVERAGE: how much of the project the tool could actually read.
 *
 * This surfaced while scanning a Python project: the tool could read none of its
 * 20 Python files, looked only at 6 SQL files, and ended the report with **"no
 * certain critical/high findings"**. In other words it gave confidence about a
 * project it could not read.
 *
 * That is the very mistake this tool exists to chase: a check returning zero for
 * something it could not measure does not say "clean", it says nothing. The
 * report now has to state what it could not read.
 */

/** Extensions the rules can actually read. */
const DESTEKLENEN = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".json", ".sql", ".prisma", ".html", ".htm", ".env", ".mdx",
  // Python is now scanned (the SQL-injection/identifier, busy_timeout and
  // spoofable-IP rules read .py). With the backend languages added, "no findings"
  // is now meaningful for those languages too.
  ".py", ".rb", ".go", ".php", ".java", ".kt",
]);

/** Extensions counted as source but which the rules CANNOT read. */
const DESTEKLENMEYEN: Record<string, string> = {
  ".rs": "Rust", ".cs": "C#",
  ".swift": "Swift", ".ex": "Elixir", ".exs": "Elixir",
  ".dart": "Dart", ".scala": "Scala", ".clj": "Clojure",
};

const ATLA = /(^|\/)(node_modules|venv|\.venv|site-packages|vendor|\.git|dist|build|\.next|out|coverage|__pycache__|target|Pods|\.tox)(\/|$)/;

export interface CoverageReport {
  /** Number of readable source files. */
  readable: number;
  /** Number of unreadable source files. */
  okunamayan: number;
  /** The unreadable languages and their file counts. */
  diller: Array<{ dil: string; count: number }>;
  /** 0-100. What percentage of the source files could be read. */
  yuzde: number;
}

export function measureCoverage(root: string): CoverageReport {
  let readable = 0;
  const dilSayisi = new Map<string, number>();

  const gez = (dizin: string): void => {
    let girdiler: string[];
    try { girdiler = readdirSync(dizin); } catch { return; }
    for (const ad of girdiler) {
      const tam = join(dizin, ad);
      const rel = relative(root, tam).replace(/\\/g, "/");
      if (ATLA.test(`/${rel}`)) continue;
      let st;
      try { st = statSync(tam); } catch { continue; }
      if (st.isDirectory()) { gez(tam); continue; }
      const ext = extname(ad).toLowerCase();
      if (DESTEKLENEN.has(ext)) readable += 1;
      else if (DESTEKLENMEYEN[ext]) {
        const dil = DESTEKLENMEYEN[ext];
        dilSayisi.set(dil, (dilSayisi.get(dil) || 0) + 1);
      }
    }
  };
  gez(root);

  const diller = [...dilSayisi.entries()]
    .map(([dil, count]) => ({ dil, count }))
    .sort((a, b) => b.count - a.count);
  const okunamayan = diller.reduce((toplam, d) => toplam + d.count, 0);
  const hepsi = readable + okunamayan;
  return {
    readable,
    okunamayan,
    diller,
    // An empty project is NOT "100% readable" — there is nothing to read, so
    // coverage is meaningless. 0 says "nothing was readable" honestly; the
    // report's notes already flag a project with no source files.
    yuzde: hepsi === 0 ? 0 : Math.round((readable / hepsi) * 100),
  };
}
