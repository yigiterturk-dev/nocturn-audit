import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A05 — build and configuration health (static, heuristic).
 *
 * Static heuristics only, with NO heavy tooling (no tsc, no build):
 *  1) Env variables used in code but undeclared in `.env.example` / `.env*`.
 *  2) TS `strict` disabled (info).
 *  3) next/vite projesinde `build` script'i yok (low).
 *  4) A relative import to a file that does not exist (best-effort, low/likely, capped).
 *
 * Not a definite vulnerability; operational and config health → low severity + likely.
 */

/** Env variables provided by the framework or host, not expected in .env.example. */
const BUILTIN_ENV = new Set([
  "NODE_ENV",
  "NODE_OPTIONS",
  "NEXT_RUNTIME",
  "NEXT_PHASE",
  "NEXT_PUBLIC_VERCEL_URL",
  "NEXT_PUBLIC_VERCEL_ENV",
  "VERCEL",
  "VERCEL_URL",
  "VERCEL_ENV",
  "VERCEL_REGION",
  "VERCEL_GIT_COMMIT_SHA",
  "CI",
  "PORT",
  "HOST",
  "HOSTNAME",
  "PWD",
  "HOME",
  "PATH",
  "TZ",
  "LANG",
  "SHELL",
  "USER",
  "ANALYZE",
  "npm_package_version",
  "npm_lifecycle_event",
]);

const ENV_FILE_RE = /(^|[/\\])\.env(\.[\w.-]+)?$/;
const SOURCE_CODE = (f: string): boolean =>
  /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f) && !ENV_FILE_RE.test(f);

/** Collect the env keys referenced in code (per file, every match). */
function referencedEnvKeys(ctx: StaticContext): Map<string, { file: string; line: number }> {
  const keys = new Map<string, { file: string; line: number }>();
  const re = /(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,})\b/g;
  for (const file of ctx.files) {
    if (!SOURCE_CODE(file)) continue;
    const content = ctx.read(file);
    if (content == null) continue;
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(lines[i])) !== null) {
        const key = m[1];
        if (key && !keys.has(key)) keys.set(key, { file, line: i + 1 });
      }
    }
  }
  return keys;
}

/** Keys declared in .env.example / .env* files. */
function definedEnvKeys(ctx: StaticContext): { keys: Set<string>; hasExample: boolean } {
  const keys = new Set<string>();
  let hasExample = false;
  const envFiles = ctx.files.filter((f) => {
    const base = f.replace(/\\/g, "/").split("/").pop() ?? "";
    return /^\.env/.test(base);
  });
  for (const f of envFiles) {
    const base = (f.replace(/\\/g, "/").split("/").pop() ?? "");
    if (/\.(example|sample|template)$/.test(base)) hasExample = true;
    const content = ctx.read(f) ?? "";
    for (const line of content.split(/\r?\n/)) {
      const km = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=/.exec(line);
      if (km) keys.add(km[1]);
    }
  }
  return { keys, hasExample };
}

const ASSET_EXT = /\.(css|scss|sass|less|styl|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|mp[34]|webm|wasm|md|txt|graphql|gql|yml|yaml|xml|csv|glb|gltf)$/i;

/** Best-effort resolution of whether a relative import exists. */
function resolvesTo(files: Set<string>, importer: string, spec: string): boolean {
  const dir = importer.replace(/\\/g, "/").split("/").slice(0, -1);
  const parts = spec.split("/");
  const stack = [...dir];
  for (const p of parts) {
    if (p === "." || p === "") continue;
    if (p === "..") stack.pop();
    else stack.push(p);
  }
  const base = stack.join("/");
  const cands = [
    base,
    // .js/.jsx was written but the source may be TS (NodeNext ESM style)
    base.replace(/\.jsx?$/, ".ts"),
    base.replace(/\.jsx?$/, ".tsx"),
  ];
  const exts = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json"];
  const idx = ["/index.ts", "/index.tsx", "/index.js", "/index.jsx"];
  for (const c of cands) {
    for (const e of exts) if (files.has(c + e)) return true;
    for (const i of idx) if (files.has(c + i)) return true;
  }
  return false;
}

const MAX_BROKEN_IMPORTS = 8;

export const buildConfig: StaticRule = {
  id: "a05-build-config-health",
  title: "Build and configuration health",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "low",
  kind: "static",
  // The rule's own code filters by JS/TS extension — in a Python or Go project it
  // can look at no file at all. Undeclared, it would return `[]` and read as "clean".
  requires: ["js"],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // --- 1) Env variables used in code but undeclared ---
    const referenced = referencedEnvKeys(ctx);
    const { keys: defined, hasExample } = definedEnvKeys(ctx);
    const undocumented: string[] = [];
    for (const [key, loc] of referenced) {
      if (BUILTIN_ENV.has(key)) continue;
      if (defined.has(key)) continue;
      undocumented.push(`${key} (${loc.file}:${loc.line})`);
    }
    if (undocumented.length > 0) {
      const list = undocumented.slice(0, 20);
      if (hasExample) {
        const sample = referenced.get(undocumented[0].split(" ")[0]);
        findings.push({
          ruleId: this.id,
          title: `Env variables used in code but undocumented in .env.example (${undocumented.length})`,
          owasp: this.owasp,
          severity: "low",
          confidence: "likely",
          description: `The code references ${undocumented.length} env variable(s) that are not declared in .env.example or any .env* file. A missing env at deploy time causes runtime errors or silently wrong behaviour. Examples: ${list.join(", ")}${undocumented.length > 20 ? " …" : ""}${
            sample ? ` (first use: ${sample.file}:${sample.line})` : ""
          }`,
          evidence: [
            // DO NOT PUT A LINE NUMBER IN THE EVIDENCE TEXT.
            //
            // `list[0]` used to read "MCP_TIMEOUT_MS (src/x.ts:104)", and a
            // finding's identity is derived from its evidence text. So adding one
            // line to the file changed the identity, the corpus verdict looked
            // "lost", and the CI gate reported a phantom regression. Line-
            // independent identity exists precisely to prevent this; the position
            // already lives in the `line` field.
            // THE IDENTITY MUST BE STABLE. This rule produces ONE finding per
            // project ("N env variables undocumented") but used to write an
            // EXAMPLE variable name into the evidence. Which variable comes first
            // changes whenever the code is touched, the identity drifts, and the
            // corpus verdict looks "lost". The variable names are already listed
            // in the description; the evidence should say WHAT the finding is.
            // THE ANCHOR BELONGS AT PROJECT LEVEL. This finding does not say
            // "there is a problem in this file", it says "N env variables are
            // undocumented in this project". Anchoring the evidence to an EXAMPLE
            // usage file made the identity unstable: which variable comes first
            // changes when the code is touched, the file changes with it, and the
            // corpus verdict looked "lost". The place to document them is .env.example.
            fileEvidence(".env.example", 1, "(env variable missing from .env.example)"),
          ],
          remediation:
            "Add these keys to .env.example with placeholder values, so the deploy environment documents which variables it needs.",
        });
      } else if (undocumented.length >= 5) {
        // No .env.example at all but the code depends on env → a single informational note.
        findings.push({
          ruleId: this.id,
          title: `No .env.example, yet the code depends on ${undocumented.length} env variable(s)`,
          owasp: this.owasp,
          severity: "info",
          confidence: "likely",
          description: `There is no .env.example, yet the code references ${undocumented.length} env variable(s). With nothing documenting them, a deploy to a fresh environment can silently miss variables. Examples: ${list.slice(0, 10).join(", ")}`,
          evidence: [fileEvidence("package.json", 1, "(.env.example yok)")],
          remediation:
            "Add a .env.example listing the required keys, without real values.",
        });
      }
    }

    // --- 2) TypeScript strict disabled ---
    const tsconfigFile = ["tsconfig.json"].find((f) => ctx.exists(f));
    if (tsconfigFile) {
      const raw = ctx.read(tsconfigFile) ?? "";
      // Strip comments roughly (tsconfig may be JSONC).
      if (/"strict"\s*:\s*false/.test(raw)) {
        findings.push({
          ruleId: this.id,
          title: "TypeScript strict mode is off",
          owasp: this.owasp,
          severity: "info",
          confidence: "likely",
          description:
            "tsconfig.json sets \"strict\": false. With strict mode off, null/undefined and type errors are not caught at compile time, so runtime failures and security holes (such as unvalidated input) slip through.",
          evidence: [fileEvidence(tsconfigFile, 1, '"strict": false')],
          remediation:
            'Set "strict": true in tsconfig.json compilerOptions and fix the type errors it surfaces.',
        });
      }
    }

    // --- 3) next/vite projesinde build script yok ---
    const fw = ctx.project.stack.framework;
    if ((fw === "next" || fw === "vite") && ctx.exists("package.json")) {
      try {
        const pkg = JSON.parse(ctx.read("package.json") ?? "{}") as {
          scripts?: Record<string, string>;
        };
        const scripts = pkg.scripts ?? {};
        if (!scripts.build) {
          findings.push({
            ruleId: this.id,
            title: "package.json'da build script'i yok",
            owasp: this.owasp,
            severity: "low",
            confidence: "likely",
            description: `This is a ${fw} project but package.json declares no "build" script. The production build step is undefined, so CI/CD or the hosting build can fail.`,
            evidence: [fileEvidence("package.json", 1, "(scripts.build yok)")],
            remediation: `Add "build": "${fw === "next" ? "next build" : "vite build"}" to scripts.`,
          });
        }
      } catch {
        /* package.json parse edilemedi → yoksay */
      }
    }

    // --- 4) A relative import to a file that does not exist (best-effort, capped) ---
    const fileSet = new Set(ctx.files.map((f) => f.replace(/\\/g, "/")));
    const importRe = /(?:import|export)[^'"]*?from\s*['"](\.\.?\/[^'"]+)['"]|(?:require|import)\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/;
    const broken: { file: string; line: number; spec: string }[] = [];
    const seen = new Set<string>();
    outer: for (const m of ctx.grep(importRe, SOURCE_CODE)) {
      const mm = new RegExp(importRe.source).exec(m.text);
      const rawSpec = mm?.[1] ?? mm?.[2];
      if (!rawSpec) continue;
      // Drop ?query / #hash suffixes (e.g. ./x.wasm?module, ./y.css?inline)
      const spec = rawSpec.replace(/[?#].*$/, "");
      if (ASSET_EXT.test(spec)) continue; // css/images/wasm etc. are not scanned → skip
      const importer = m.file.replace(/\\/g, "/");
      if (resolvesTo(fileSet, importer, spec)) continue;
      const key = `${importer}:${spec}`;
      if (seen.has(key)) continue;
      seen.add(key);
      broken.push({ file: m.file, line: m.line, spec });
      if (broken.length >= MAX_BROKEN_IMPORTS) break outer;
    }
    for (const b of broken) {
      findings.push({
        ruleId: this.id,
        title: `Unresolvable relative import: ${b.spec}`,
        owasp: this.owasp,
        severity: "low",
        confidence: "likely",
        description: `${b.file}:${b.line} → "${b.spec}" does not exist in the project (the file may have been moved, deleted, or the path is wrong). The build can break. Note: path aliases (@/...) are out of scope; only ./ and ../ imports are checked.`,
        evidence: [fileEvidence(b.file, b.line, b.spec)],
        remediation: "Fix the import path, or restore the missing file.",
      });
    }

    return findings;
  },
};
