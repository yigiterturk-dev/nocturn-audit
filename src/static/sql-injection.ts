import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A03 — SQL enjeksiyonu: template literal / string birleştirme ile SQL,
 * içine değişken (özellikle istek girdisi) gömülmüş.
 */

// SELECT/INSERT/UPDATE/DELETE içeren template literal + ${...} interpolasyonu
const SQL_TEMPLATE =
  /(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|FROM)\b[\s\S]{0,120}\$\{[^}]+\}/i;
// string + değişken birleştirme ile SQL
const SQL_CONCAT =
  /["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^"'`]*["'`]\s*\+\s*\w+/i;
// ham sorgu çağrıları
const RAW_QUERY =
  /\.(query|raw|unsafe|execute|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(/;

const INPUT_HINT =
  /(req\.|params|searchParams|query\.|body|input|formData|request\.)/;

export const sqlInjection: StaticRule = {
  id: "a03-sql-injection",
  title: "Olası SQL enjeksiyonu (string ile sorgu oluşturma)",
  owasp: "A03:2021-Injection",
  severity: "critical",
  kind: "static",
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

        const templ = SQL_TEMPLATE.test(window);
        const concat = SQL_CONCAT.test(window);
        const rawUnsafe =
          /\$(queryRawUnsafe|executeRawUnsafe)/.test(raw) ||
          (RAW_QUERY.test(raw) && /\$\{|["'`][^"'`]*["'`]\s*\+/.test(window));

        if (!templ && !concat && !rawUnsafe) continue;

        // parametreli değilse ve girdi ihtimali varsa daha kritik
        const inputNear = INPUT_HINT.test(
          lines.slice(Math.max(0, i - 3), i + 4).join("\n"),
        );
        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: inputNear ? "critical" : "high",
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
