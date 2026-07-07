import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A03 — SQL enjeksiyonu: template literal / string birleştirme ile SQL,
 * içine değişken (özellikle istek girdisi) gömülmüş.
 */

// Gerçek bir SQL İFADESİ imzası (tek kelime "from"/"where" değil — çok-kelimeli
// gerçek statement). Tailwind `from-blue-500` / JSX gibi FP'leri eler.
const SQL_STMT =
  /\bSELECT\b[\s\S]{0,200}?\bFROM\b|\bINSERT\s+INTO\s+["'`]?\w|\bUPDATE\s+["'`]?\w[\s\S]{0,80}?\bSET\b|\bDELETE\s+FROM\s+["'`]?\w/i;
// ham sorgu sürücü çağrıları (parametreli olmayan).
const RAW_QUERY =
  /\.(query|raw|unsafe|execute|prepare)\s*\(|\$queryRawUnsafe|\$executeRawUnsafe|\bknex\.raw\b|\bsql`/;
// SQL string'ine değişken interpolasyonu/birleştirmesi.
const SQL_INTERP = /\$\{[^}]+\}|["'`][^"'`]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"'`]*["'`]\s*\+\s*\w/i;
// JSX/TSX render bağlamı → SQL değil, tamamen ele.
const JSX_CONTEXT =
  /className=|classList|<\/?[A-Za-z][\w.]*[\s/>]|style=\{|tw`|clsx\(|cn\(|cva\(/;
// Supabase/PostgREST ORM query builder (parametreli) → SQL-injection kapsamı dışı.
const ORM_BUILDER =
  /\.from\(\s*["'`]\w[\s\S]{0,200}?\.(select|eq|neq|or|and|ilike|like|gte|lte|gt|lt|in|match|contains|filter)\s*\(/i;
// HTTP body (fetch/axios) JSON.stringify → SQL değil.
const HTTP_BODY = /(fetch\s*\(|axios|\.post\(|\.put\(|body\s*:)/i;

const INPUT_HINT =
  /(req\.|params|searchParams|query\.|body|input|formData|request\.)/;

export const sqlInjection: StaticRule = {
  id: "a03-sql-injection",
  title: "Olası SQL enjeksiyonu (string ile sorgu oluşturma)",
  owasp: "A03:2021-Injection",
  severity: "high",
  kind: "static",
  // Paternsel tespit; elle doğrulama gerekir.
  confidence: "olası",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (/(test|spec|fixtures?)/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        const window = lines.slice(i, i + 3).join("\n");

        // JSX/TSX render bağlamı → SQL değil, ele.
        if (JSX_CONTEXT.test(raw)) continue;

        // Gerçek SQL bağlamı olmalı: ya bir SQL statement imzası ya da ham sürücü çağrısı.
        const hasSqlStmt = SQL_STMT.test(window);
        const hasDriver = RAW_QUERY.test(raw);
        const rawUnsafe = /\$(queryRawUnsafe|executeRawUnsafe)/.test(raw);
        const hasInterp = SQL_INTERP.test(window);

        // İnterpolasyon/birleştirme veya ham-unsafe çağrı olmadan SQLi olmaz.
        if (!rawUnsafe && !hasInterp) continue;
        // SQL bağlamı doğrulanmadıysa (statement imzası ya da sürücü çağrısı) ele.
        if (!rawUnsafe && !hasSqlStmt && !hasDriver) continue;
        // Supabase/PostgREST ORM builder → parametreli, ele.
        if (ORM_BUILDER.test(window)) continue;
        // Ham SQL değil de HTTP body (fetch/axios) JSON.stringify ise ele.
        if (!hasSqlStmt && !hasDriver && HTTP_BODY.test(window)) continue;

        // parametreli değilse ve girdi ihtimali varsa daha kritik
        const inputNear = INPUT_HINT.test(
          lines.slice(Math.max(0, i - 3), i + 4).join("\n"),
        );
        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          // Sezgisel kural: yalnızca kullanıcı girdisi ham SQL'e aktığında yüksek;
          // aksi halde düşük (korroborasyonsuz sezgisel → düşük).
          severity: inputNear ? "high" : "low",
          description: inputNear
            ? "SQL sorgusu string/template ile oluşturuluyor ve yakında kullanıcı girdisi (req/params/body/query) var. Parametreleştirme yoksa doğrudan SQL enjeksiyonu mümkün."
            : "SQL sorgusu string birleştirme/template ile oluşturuluyor. Değişken interpolasyonu enjeksiyon riski taşır; parametreli sorgu kullanılmalı.",
          evidence: [fileEvidence(file, i + 1, raw)],
          remediation:
            "Parametreli sorgu / prepared statement kullanın (ör. sql`... ${param}` tagged template, db.query(text, [params]), Prisma parametreli API). Ham string birleştirmeyi kaldırın.",
        });
        break;
      }
    }
    return findings;
  },
};
