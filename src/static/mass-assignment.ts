import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A01 — Mass assignment (aşırı atama).
 *
 * Kullanıcı girdisinin (req.body / req.json() / params) doğrulanmadan ve alan seçilmeden
 * doğrudan bir DB create/update çağrısına yayılması/geçirilmesi. Saldırgan beklenmeyen
 * alanları (ör. isAdmin, role, balance) set edip yetki yükseltebilir.
 */

const MUTATION_SINK =
  /\.(create|createMany|update|updateMany|upsert|insert|save)\s*\(|\.values\s*\(|new\s+[A-Z]\w*\s*\(/;

// Ham kullanıcı girdisi ifadeleri.
const RAW_INPUT_SRC = /req\.body|request\.body|req\.query|req\.params|await\s+req\.json\(\)/;

const isServerFile = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return /\.(ts|js|mjs|cjs)$/.test(f) && !/\.d\.ts$/.test(f);
};

export const massAssignment: StaticRule = {
  id: "a01-mass-assignment",
  title: "Mass assignment (doğrulanmamış girdi DB'ye yayılıyor)",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  cwe: "CWE-915",
  kind: "static",
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (!isServerFile(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      // tainted: ham girdiden gelen değişkenler
      const tainted = new Set<string>();
      // validated: şema doğrulamasından geçmiş değişkenler → güvenli
      const validated = new Set<string>();
      for (const raw of lines) {
        const dm = /\b(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*([^;]+)/.exec(raw);
        if (!dm) {
          // destructuring: const { a } = schema.parse(...)
          const pm = /\b(?:const|let|var)\s*\{[^}]*\}\s*=\s*([^;]+)/.exec(raw);
          if (pm && /\.(safe)?parse\s*\(|\.validate(?:Sync|Async)?\s*\(|pick\s*\(/.test(pm[1])) {
            // destructure edilmiş alanlar zaten seçilmiş → tainted değil
          }
          continue;
        }
        const name = dm[1];
        const rhs = dm[2];
        if (/\.(safe)?parse\s*\(|\.validate(?:Sync|Async)?\s*\(|zod|joi\.|yup\./.test(rhs)) {
          validated.add(name);
        } else if (RAW_INPUT_SRC.test(rhs)) {
          tainted.add(name);
        }
      }

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!MUTATION_SINK.test(raw)) continue;

        // Doğrulama zaten yapılmışsa (satırda .parse) atla
        if (/\.(safe)?parse\s*\(/.test(raw)) continue;

        // (a) doğrudan ham girdi: data: req.body | ...req.body | (req.body) | values(req.body)
        const directRaw =
          new RegExp(
            `(\\.\\.\\.\\s*(?:${RAW_INPUT_SRC.source})|` +
              `data\\s*:\\s*(?:${RAW_INPUT_SRC.source})|` +
              `values\\s*\\(\\s*(?:${RAW_INPUT_SRC.source})|` +
              `\\(\\s*(?:${RAW_INPUT_SRC.source})\\s*\\))`,
          ).test(raw);

        // (b) tainted değişken yayılıyor/geçiriliyor (validated değilse)
        let taintedVar = false;
        for (const v of tainted) {
          if (validated.has(v)) continue;
          if (
            new RegExp(`\\.\\.\\.\\s*${v}\\b|data\\s*:\\s*${v}\\b|values\\s*\\(\\s*${v}\\b`).test(raw)
          ) {
            taintedVar = true;
            break;
          }
        }

        if (directRaw || taintedVar) {
          findings.push({
            ruleId: this.id,
            title: this.title,
            owasp: this.owasp,
            severity: "high",
            cwe: this.cwe,
            description:
              "Kullanıcı girdisi (req.body / req.json()) alan seçimi ve doğrulama yapılmadan doğrudan bir DB create/update çağrısına veriliyor. Saldırgan beklenmeyen kolonları (role, isAdmin, ownerId, balance vb.) set ederek yetki yükseltebilir veya veriyi bozabilir.",
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation:
              "Girdiyi bir şema ile (zod/yup/joi) doğrulayıp yalnızca izin verilen alanları seçin (allowlist). Ham objeyi ORM'e yaymayın.",
            remediationCode:
              "const input = schema.parse(await req.json()); // sadece izinli alanlar\n" +
              "await prisma.user.update({ where: { id }, data: { name: input.name } });",
          });
        }
      }
    }
    return findings;
  },
};
