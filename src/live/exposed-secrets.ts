import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveContext, LiveRule } from "../core/rule.js";
import type { Severity } from "../core/severity.js";

/**
 * A05 (live) — exposed sensitive files (extended).
 *
 * `a05-live-exposed-files` covers /.env, /.git/config and /.git/HEAD; this rule
 * COMPLEMENTS it (no overlap): .env.local/.env.production, .env backups,
 * config.json, database dumps and backups, and exposed source maps (.js.map).
 *
 * SPA 200-catch-all protection: every target has a signature confirming the
 * response REALLY is that file (skip otherwise). Confirmed findings → "certain".
 */

interface Target {
  path: string;
  severity: Severity;
  signature: RegExp;
  title: string;
  fix: string;
}

const TARGETS: Target[] = [
  {
    path: "/.env.local",
    severity: "critical",
    signature: /^[A-Z0-9_]+\s*=/m,
    title: "Publicly reachable .env.local file",
    fix: "Stop serving .env.local publicly, fix the hosting rewrite/ignore rules, and revoke every leaked secret.",
  },
  {
    path: "/.env.production",
    severity: "critical",
    signature: /^[A-Z0-9_]+\s*=/m,
    title: "Publicly reachable .env.production file",
    fix: "Stop serving .env.production publicly, and revoke and reissue every leaked secret.",
  },
  {
    path: "/.env.bak",
    severity: "critical",
    signature: /^[A-Z0-9_]+\s*=/m,
    title: "Publicly reachable .env backup (.env.bak)",
    fix: "Remove the backup env file and revoke the leaked secrets.",
  },
  {
    path: "/backup.sql",
    severity: "high",
    signature: /(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump|DROP TABLE)/i,
    title: "Publicly reachable database backup (backup.sql)",
    fix: "Remove the database dump from the web root; if it leaked, assess the affected records and secrets.",
  },
  {
    path: "/dump.sql",
    severity: "high",
    signature: /(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump|DROP TABLE)/i,
    title: "Publicly reachable database dump (dump.sql)",
    fix: "Remove the database dump from the web root.",
  },
  {
    path: "/database.sql",
    severity: "high",
    signature: /(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump|DROP TABLE)/i,
    title: "Publicly reachable database schema/dump (database.sql)",
    fix: "Remove the SQL file from the web root.",
  },
];

/** Does config.json contain secret-like keys (otherwise it is a benign public config)? */
const CONFIG_SECRET_RE =
  /"(?:[a-zA-Z_]*(?:password|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|service[_-]?role|client[_-]?secret)[a-zA-Z_]*)"\s*:\s*"[^"]{6,}"/i;

/** Source map signature. */
const SOURCEMAP_RE = /"version"\s*:\s*3[\s\S]*"sources"\s*:/;

/** Pull the first real JS bundle path out of the "/" response (for the source map check). */
function firstScriptSrc(html: string): string | null {
  const re = /<script[^>]+src=["']([^"']+\.js)(\?[^"']*)?["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const src = m[1];
    // check same-origin (relative) bundles only
    if (src.startsWith("/") && !src.startsWith("//")) return src;
  }
  return null;
}

async function checkConfigJson(ctx: LiveContext, findings: Finding[], ruleId: string, owasp: Finding["owasp"]): Promise<void> {
  const res = await ctx.probe("/config.json");
  if (!res.ok || res.status !== 200) return;
  // JSON plus a secret-like key is required (to filter out public config.json files).
  if (!/^\s*[[{]/.test(res.bodySnippet)) return;
  if (!CONFIG_SECRET_RE.test(res.bodySnippet)) return;
  findings.push({
    ruleId,
    title: "Publicly reachable config.json containing secrets",
    owasp,
    severity: "high",
    confidence: "certain",
    cwe: "CWE-538",
    description:
      "/config.json returned 200 and contains secret-like keys (password/secret/token/apiKey). Configuration secrets are exposed to the internet.",
    evidence: [httpEvidence(res.requestLine, `HTTP ${res.status}\n${res.bodySnippet.slice(0, 200)}`)],
    remediation:
      "Remove the secret-bearing config.json from the public directory, move the secrets into server-side env, and rotate them.",
  });
}

async function checkSourceMap(ctx: LiveContext, findings: Finding[], ruleId: string, owasp: Finding["owasp"]): Promise<void> {
  const root = await ctx.probe("/");
  if (!root.ok || root.status !== 200) return;
  const script = firstScriptSrc(root.bodySnippet);
  if (!script) return;
  const mapRes = await ctx.probe(`${script}.map`);
  if (!mapRes.ok || mapRes.status !== 200) return;
  if (!SOURCEMAP_RE.test(mapRes.bodySnippet)) return;
  findings.push({
    ruleId,
    title: "Publicly reachable source map (.js.map)",
    owasp,
    severity: "medium",
    confidence: "certain",
    cwe: "CWE-540",
    description: `${script}.map returned 200 with a valid source map signature. Source maps leak your original (pre-minification) code, its comments and your internal path structure.`,
    evidence: [httpEvidence(mapRes.requestLine, `HTTP ${mapRes.status}\n${mapRes.bodySnippet.slice(0, 160)}`)],
    remediation:
      "Disable source map generation in production (Next: productionBrowserSourceMaps:false, Vite: build.sourcemap:false), or block public access to .map files.",
  });
}

export const liveExposedSecrets: LiveRule = {
  id: "a05-live-exposed-secrets",
  title: "Live: exposed env backup, database dump, config or source map",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "high",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const t of TARGETS) {
      const res = await ctx.probe(t.path);
      if (!res.ok || res.status !== 200) continue;
      // Filter out the SPA fallback (index.html): skip when the signature is absent.
      if (!t.signature.test(res.bodySnippet)) continue;
      findings.push({
        ruleId: this.id,
        title: t.title,
        owasp: this.owasp,
        severity: t.severity,
        confidence: "certain",
        cwe: "CWE-538",
        description: `${t.path} returned 200 and its content matched the real file signature. A sensitive file is exposed to the internet.`,
        evidence: [httpEvidence(res.requestLine, `HTTP ${res.status}\n${res.bodySnippet.slice(0, 200)}`)],
        remediation: t.fix,
      });
    }
    await checkConfigJson(ctx, findings, this.id, this.owasp);
    await checkSourceMap(ctx, findings, this.id, this.owasp);
    return findings;
  },
};
