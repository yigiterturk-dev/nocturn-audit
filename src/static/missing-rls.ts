import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A01/A05 — Eksik Row Level Security (Supabase / Postgres).
 *
 * Parses SQL schema and migration files for:
 *  - tables created in the `public` schema that never get `enable row level security`,
 *  - tables with RLS enabled but no `create policy` at all.
 *
 * (Use of the service_role key on the client is a separate rule — a01-supabase-service-role-key.)
 */

// Capture the table name together with its schema prefix.
const CREATE_TABLE =
  /create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z0-9_."]+)/gi;
const ENABLE_RLS =
  /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([a-zA-Z0-9_."]+)\s+enable\s+row\s+level\s+security/gi;
const CREATE_POLICY =
  /create\s+policy\s+[^;]*?\bon\s+([a-zA-Z0-9_."]+)/gi;

interface TableRef {
  schema: string;
  name: string;
}

/** "public"."users" | public.users | users → {schema,name} */
function parseTable(rawId: string): TableRef {
  const parts = rawId
    .split(".")
    .map((p) => p.replace(/["`]/g, "").trim())
    .filter(Boolean);
  if (parts.length >= 2) {
    return { schema: parts[0].toLowerCase(), name: parts[1].toLowerCase() };
  }
  return { schema: "public", name: (parts[0] ?? "").toLowerCase() };
}

// Supabase-managed schemas — RLS is already handled there, skip.
const MANAGED_SCHEMAS = new Set([
  "auth",
  "storage",
  "realtime",
  "supabase_functions",
  "vault",
  "extensions",
  "graphql",
  "graphql_public",
  "pgsodium",
  "cron",
]);

function collectMatches(
  content: string,
  re: RegExp,
): Array<{ table: TableRef; index: number }> {
  const out: Array<{ table: TableRef; index: number }> = [];
  const rx = new RegExp(re.source, re.flags);
  let m: RegExpExecArray | null;
  while ((m = rx.exec(content)) !== null) {
    out.push({ table: parseTable(m[1]), index: m.index });
    if (m.index === rx.lastIndex) rx.lastIndex++;
  }
  return out;
}

function lineOf(content: string, index: number): number {
  return content.slice(0, index).split(/\r?\n/).length;
}

// Prisma/Drizzle ORM migration paths — these ORMs do not generate RLS by design and
// use a server-side privileged (owner) connection; RLS is architecturally n/a.
const ORM_MIGRATION_PATH =
  /(^|\/)(prisma\/migrations|drizzle)(\/|$)|\.prisma$/i;

/**
 * The rule is only meaningful in a REAL Supabase client project: the repository
 * must depend on @supabase/supabase-js (or @supabase/ssr) AND have client-side
 * access with an anon/publishable key. Otherwise (Neon/plain Postgres + server-side
 * owner connection, Prisma/Drizzle) RLS tehdit modeli na.
 */
function isSupabaseClientProject(ctx: StaticContext): boolean {
  const pkg = ctx.read("package.json");
  const hasSupabaseDep = !!pkg && /@supabase\/(supabase-js|ssr)/.test(pkg);
  if (hasSupabaseDep) {
    // If stack.db is supabase, OR there is anon/publishable client access, it is the Supabase architecture.
    if (ctx.project.stack.db === "supabase") {
      const anonClient =
        ctx.grep(
          /(NEXT_PUBLIC_SUPABASE_ANON_KEY|SUPABASE_ANON_KEY|PUBLISHABLE|createBrowserClient|createClientComponentClient|createPagesBrowserClient|anonKey|supabaseAnonKey)/i,
        ).length > 0;
      if (anonClient) return true;
    }
  }
  return ctx.project.stack.db === "supabase" &&
    ctx.grep(
      /(NEXT_PUBLIC_SUPABASE_ANON_KEY|createBrowserClient|createClientComponentClient|anonKey)/i,
    ).length > 0;
}

export const missingRls: StaticRule = {
  id: "a01-missing-rls",
  title: "Eksik Row Level Security (RLS)",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  cwe: "CWE-284",
  kind: "static",
  // Without a SQL schema or migration file the RLS/FK state CANNOT BE READ — to
  // say "RLS is missing" you first have to see the table definition.
  requires: ["sql"],
  // A public table without RLS in the SQL schema → deterministic (SQL parse).
  confidence: "certain",
  run(ctx: StaticContext): Finding[] {
    // Only real Supabase client projects (PostgREST access with an anon/publishable
    // key). With Neon/plain Postgres plus a Prisma/Drizzle server-side owner
    // connection the RLS threat model is n/a → do not run at all.
    if (!isSupabaseClientProject(ctx)) return [];

    const sqlFiles = ctx.files.filter((f) => {
      const p = f.replace(/\\/g, "/");
      // Drop Prisma/Drizzle migration files entirely.
      if (ORM_MIGRATION_PATH.test(p)) return false;
      return /\.sql$/i.test(p);
    });
    if (sqlFiles.length === 0) return [];

    // Migrations may be spread over several files → collect them all.
    const created = new Map<string, { file: string; line: number }>();
    const rlsEnabled = new Set<string>();
    const policied = new Set<string>();

    for (const file of sqlFiles) {
      const content = ctx.read(file);
      if (!content) continue;

      for (const { table, index } of collectMatches(content, CREATE_TABLE)) {
        if (MANAGED_SCHEMAS.has(table.schema) || !table.name) continue;
        const key = `${table.schema}.${table.name}`;
        if (!created.has(key)) {
          created.set(key, { file, line: lineOf(content, index) });
        }
      }
      for (const { table } of collectMatches(content, ENABLE_RLS)) {
        rlsEnabled.add(`${table.schema}.${table.name}`);
      }
      for (const { table } of collectMatches(content, CREATE_POLICY)) {
        policied.add(`${table.schema}.${table.name}`);
      }
    }

    const findings: Finding[] = [];
    for (const [key, loc] of created) {
      const [, name] = key.split(".");
      if (!rlsEnabled.has(key)) {
        findings.push({
          ruleId: this.id,
          title: `Table without RLS enabled: ${name}`,
          owasp: this.owasp,
          severity: "high",
          cwe: this.cwe,
          description:
            `Table \`${key}\` is created but never gets \`enable row level security\` anywhere. ` +
            "In Supabase, the anon and authenticated keys reach this table directly through PostgREST; without RLS every row is readable and writable.",
          evidence: [
            fileEvidence(
              loc.file,
              loc.line,
              `create table ${key} (RLS yok)`,
            ),
          ],
          remediation:
            "Enable RLS on the table and define at least one restrictive policy.",
          remediationCode:
            `alter table ${key} enable row level security;\n` +
            `create policy "owner_select" on ${key}\n` +
            `  for select using (auth.uid() = user_id);`,
        });
      }
      // NOTE: "RLS on + no policy" is fail-closed (default deny) — the safest
      // possible state, NOT a hole; it is a deliberate service-role-only pattern.
      // So we no longer report it (the old medium finding was an FP).
    }
    return findings;
  },
};
