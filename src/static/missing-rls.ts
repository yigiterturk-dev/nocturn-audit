import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A01/A05 — Eksik Row Level Security (Supabase / Postgres).
 *
 * SQL şema + migration dosyalarını ayrıştırır:
 *  - `public` şemasında oluşturulup hiç `enable row level security` almayan tablolar,
 *  - RLS açık ama hiç `create policy` tanımlanmamış tablolar.
 *
 * (service_role anahtarının client'ta kullanımı ayrı kuralla — a01-supabase-service-role-key.)
 */

// Şema öneki ile birlikte tablo adını yakala.
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

// Supabase yönetimli şemalar — RLS zaten yönetilir, atla.
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

// Prisma/Drizzle ORM migration yolları — bu ORM'ler tasarımı gereği RLS üretmez ve
// server-side privileged (owner) connection kullanır; RLS mimari olarak uygulanamaz.
const ORM_MIGRATION_PATH =
  /(^|\/)(prisma\/migrations|drizzle)(\/|$)|\.prisma$/i;

/**
 * Kural yalnızca GERÇEK Supabase istemci projelerinde anlamlıdır: repoda
 * @supabase/supabase-js (veya @supabase/ssr) bağımlılığı VE anon/publishable
 * anahtarla client-side erişim olmalı. Aksi halde (Neon/düz Postgres + server-side
 * owner connection, Prisma/Drizzle) RLS tehdit modeli uygulanamaz.
 */
function isSupabaseClientProject(ctx: StaticContext): boolean {
  const pkg = ctx.read("package.json");
  const hasSupabaseDep = !!pkg && /@supabase\/(supabase-js|ssr)/.test(pkg);
  if (hasSupabaseDep) {
    // stack.db supabase VEYA anon/publishable client erişimi varsa Supabase mimarisi.
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
  // SQL şemasında RLS'siz public tablo → deterministik (SQL parse).
  confidence: "kesin",
  run(ctx: StaticContext): Finding[] {
    // Yalnızca gerçek Supabase istemci projeleri (anon/publishable key ile PostgREST
    // erişimi). Neon/düz-Postgres + Prisma/Drizzle server-side owner connection ise
    // RLS tehdit modeli uygulanamaz → hiç çalıştırma.
    if (!isSupabaseClientProject(ctx)) return [];

    const sqlFiles = ctx.files.filter((f) => {
      const p = f.replace(/\\/g, "/");
      // Prisma/Drizzle migration dosyalarını tamamen ele.
      if (ORM_MIGRATION_PATH.test(p)) return false;
      return /\.sql$/i.test(p);
    });
    if (sqlFiles.length === 0) return [];

    // Migration'lar birden çok dosyaya yayılabilir → tümünü topla.
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
          title: `RLS açılmamış tablo: ${name}`,
          owasp: this.owasp,
          severity: "high",
          cwe: this.cwe,
          description:
            `\`${key}\` tablosu oluşturuluyor ama hiçbir yerde \`enable row level security\` almıyor. ` +
            "Supabase'de anon/authenticated anahtarları PostgREST üzerinden bu tabloya doğrudan erişebilir; RLS yoksa tüm satırlar okunabilir/yazılabilir.",
          evidence: [
            fileEvidence(
              loc.file,
              loc.line,
              `create table ${key} (RLS yok)`,
            ),
          ],
          remediation:
            "Tabloda RLS'i açın ve en az bir kısıtlayıcı policy tanımlayın.",
          remediationCode:
            `alter table ${key} enable row level security;\n` +
            `create policy "owner_select" on ${key}\n` +
            `  for select using (auth.uid() = user_id);`,
        });
      }
      // NOT: "RLS açık + policy yok" durumu fail-closed (default deny) — mümkün olan
      // en güvenli durumdur, açık DEĞİLDİR; bilinçli service-role-only desendir.
      // Bu yüzden artık bulgu üretmiyoruz (eski medium bulgu FP idi).
    }
    return findings;
  },
};
