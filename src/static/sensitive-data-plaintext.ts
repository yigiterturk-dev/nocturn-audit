import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";
import { parametreVeOzellikSatirlari } from "../core/ast.js";

/**
 * A02 — sensitive data stored in plaintext.
 *
 * Looks at Prisma / Drizzle / raw SQL schemas and migrations, and at database
 * write calls in code, for sensitive fields — national id, SSN, passport, card
 * number, CVV, IBAN, health/medical data, OAuth/API tokens, private keys — held
 * in plaintext types (`text`/`varchar`/`String`) with no field-level encryption.
 */

// Sensitive field names (column / field / DB name). Kept narrow with \b boundaries.
const SENSITIVE_NAME =
  /\b(tc[_-]?kimlik(?:[_-]?no)?|tckn|kimlik[_-]?no|ssn|social[_-]?security(?:[_-]?number)?|passport(?:[_-]?no)?|pasaport|credit[_-]?card|card[_-]?number|card[_-]?no|cardnum|cc[_-]?number|cvv|cvc|iban|health|medical|saglik|sağlık|hasta[_-]?(?:no|kayit)|diagnos(?:is|e)|tani|tanı|biometric|biyometrik|oauth[_-]?token|refresh[_-]?token|access[_-]?token|api[_-]?key|secret[_-]?key|private[_-]?key)\b/i;

// Plaintext types (SQL + Prisma + Drizzle).
const PLAINTEXT_TYPE =
  /\b(text|varchar|char|citext|nvarchar|longtext|mediumtext|string)\b|\btext\s*\(|\bvarchar\s*\(|\bchar\s*\(/i;

// Encryption or protection signals → the line counts as safe.
// Not: `encrypt\w*` / `decrypt\w*`, `encryptToken(...)` / `decryptToken(...)` gibi
// also catches wrapper function names (\bencrypt\b was MISSING those).
const ENCRYPTION_HINT =
  /(bytea|pgp_sym_encrypt|pgp_pub_encrypt|pgcrypto|encrypt\w*|decrypt\w*|encrypted|ciphertext|cipher|\bvault\b|EncryptedField|@Encrypted|@encrypted|crypto\.|createCipher|libsodium|sodium|kms|hashed|bcrypt|argon2|scrypt|\.hash\b)/i;

// Is the value itself an encryption or hash wrapper (e.g. encryptToken(x), hash(x))?
const VALUE_IS_PROTECTED =
  /\b(encrypt\w*|decrypt\w*|cipher\w*|hash\w*|bcrypt|argon2|scrypt|kms|seal\w*|vault)\s*\(/i;

// Code side: database write calls.
const DB_MUTATION =
  /\.(insert|create|createMany|update|updateMany|upsert|values|set|save)\s*\(|INSERT\s+INTO|UPDATE\s+\w+\s+SET/i;

// Code side: a token or secret assigned straight into a database object.
const TOKEN_PROP =
  /\b(access[_-]?token|refresh[_-]?token|oauth[_-]?token|api[_-]?key|apiKey|secret[_-]?key|client[_-]?secret)\s*:\s*([^,\n}]+)/i;

// A type annotation / env read / placeholder → not real storage.
const NOT_STORED_VALUE =
  /^\s*(string|number|boolean|any|unknown|String|Boolean|Prisma\.|z\.|process\.env|import\.meta|["'`]?<)/;

const DB_MUTATION_SINK =
  /\.(insert|create|createMany|update|updateMany|upsert|values|save)\s*\(/i;

// Generated files and type declarations → skip.
const isGenerated = (file: string): boolean =>
  /(^|\/)(generated|\.prisma|prisma\/client)(\/|$)|\.d\.ts$/.test(
    file.replace(/\\/g, "/"),
  );

const isSchemaFile = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /\.(sql|prisma)$/.test(f) ||
    /(^|\/)(schema|migrations?|models?|db)(\/|\.|$)/i.test(f)
  );
};

const looksLikeColumnDef = (line: string): boolean => {
  // SQL kolon:  col_name TYPE ...   |  Prisma: field  String  |  Drizzle: field: text('col')
  return (
    /^\s*["'`]?\w+["'`]?\s+\w/.test(line) || // SQL "name TYPE"
    /^\s*\w+\s*:?\s*(text|varchar|char|string)\s*[\(:]/i.test(line) || // drizzle/prisma
    /^\s*\w+\s+String\b/.test(line) // prisma
  );
};

export const sensitiveDataPlaintext: StaticRule = {
  id: "a02-sensitive-data-plaintext",
  title: "Sensitive field stored in plaintext",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  cwe: "CWE-311",
  kind: "static",
  // NO PRECONDITIONS. The first declaration said "js" — which was WRONG: this
  // rule also reads `.sql` and `.prisma` schema files. In a Python + SQL project
  // it silently never ran, so the wrong declaration produced exactly the
  // blindness it was meant to prevent. The second canary (SQLite/Python) caught it.
  requires: [],
  // A plaintext sensitive column in the schema → deterministic.
  confidence: "certain",
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (isGenerated(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const schema = isSchemaFile(file);
      // In JS/TS the "name: type" shape can be a COLUMN or a PARAMETER. The tree
      // makes the distinction: `function f(apiKey: string)` is not storage, the
      // value goes into the function. In two projects this was half the findings.
      const tree = ctx.ast(file);
      const lineKind = tree ? parametreVeOzellikSatirlari(tree) : null;
      const fileHasMutation = DB_MUTATION.test(content);
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (ENCRYPTION_HINT.test(raw)) continue;
        // A line that is only a parameter declaration → no storage.
        if (lineKind && lineKind.parametre.has(i + 1) && !lineKind.ozellik.has(i + 1))
          continue;
        // Comment lines → not a real schema or persistence flow, drop.
        if (/^\s*(\/\/|\*|\/\*)/.test(raw)) continue;
        // TİP BİLDİRİMİ DEPOLAMA DEĞİLDİR (gerçek vaka, 2026-09-22):
        //   `private readonly config: () => { apiKey: string ... }` — bir hukuk SaaS llm.ts
        //   `const diagnosis: string[] = []` — report.ts
        // sensitive ad + "string" kelimesi TİP iken bulgu üretiliyordu (2 FP).
        // Değer bir tür adı / boş başlatıcıysa satır atlanır — şema dosyalarında
        // DEĞİL (orada `apiKey String` gerçek plaintext kolonudur).
        // Sınır: yalnız const/readonly ALAN bildirimleri. Fonksiyon imza
        // satırları (export async function listSites(fetchFn: FetchLike...))
        // ATLANMAZ — oradaki ': string' parametre tipidir ama satır gerçek bir
        // bulgunun kanıtı olabilir (gsc.ts:755 TP'si canary'den geldi).
        if (!schema && !/\bfunction\b/.test(raw) &&
            (/(?:const|readonly)\s+\w+\s*:\s*(?:string(?:\[\])?|number|boolean|object|Date|Buffer|Record<[^>]*>|Promise<[^>]*>)\b/i.test(raw) ||
             /readonly\s+\w+\s*:\s*\(/.test(raw)) &&
            !/["'`]|process\.env|import\.meta/.test(raw)) {
          continue;
        }

        // (A) Schema/migration: a plaintext column with a sensitive name.
        // This is ONLY a DDL column definition — there is no evidence of a real
        // plaintext-persist data flow or a decrypt bypass. So it is LOW at most (a
        // compliance note), never high. Framework-mandated auth adapter fields
        // (NextAuth/Auth.js Account: refresh_token/access_token/id_token) are allowlisted.
        const isFrameworkAuthField =
          /\b(refresh_token|access_token|id_token|oauth_token|session_token)\b/i.test(
            raw,
          );
        if (
          (schema || /\.(ts|js)$/.test(file)) &&
          SENSITIVE_NAME.test(raw) &&
          PLAINTEXT_TYPE.test(raw) &&
          looksLikeColumnDef(raw) &&
          !isFrameworkAuthField
        ) {
          const key = `${file}:${i}:col`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              ruleId: this.id,
              title: this.title + " (schema column definition — compliance note)",
              owasp: this.owasp,
              severity: "low",
              confidence: "likely",
              cwe: this.cwe,
              description:
                "A sensitive field (national id, SSN, card, CVV, IBAN, health data, token) appears to be declared with a plaintext column type (text/varchar/String). This is only a schema/DDL definition; it does not prove the data is actually stored unencrypted. Without field-level encryption (pgcrypto or the application layer), a database backup or leak exposes it — review this for compliance.",
              evidence: [fileEvidence(file, i + 1, raw)],
              remediation:
                "Encrypt the field in the application before storing it, or keep it encrypted with pgcrypto (pgp_sym_encrypt) and make the column bytea. For card data, prefer tokenisation or a PCI-DSS compliant provider.",
              remediationCode:
                "-- field-level encryption with pgcrypto\n" +
                "-- INSERT: pgp_sym_encrypt($1, current_setting('app.enc_key'))\n" +
                "-- SELECT: pgp_sym_decrypt(col, current_setting('app.enc_key'))\n" +
                "ALTER TABLE t ALTER COLUMN sensitive_col TYPE bytea USING pgp_sym_encrypt(sensitive_col, :key);",
            });
          }
        }

        // (B) Code side: a token or secret assigned straight into a DB object.
        // Reduce FPs: require a DB mutation sink nearby (same line or the previous
        // four), and require the value not to be a type, env read or placeholder.
        if (fileHasMutation && /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file)) {
          const tm = TOKEN_PROP.exec(raw);
          const nearMutation =
            DB_MUTATION_SINK.test(raw) ||
            lines.slice(Math.max(0, i - 4), i).some((l) => DB_MUTATION_SINK.test(l));
          // NextAuth/Auth.js adapter context: the adapter itself stores the Account
          // model's token fields in plaintext (a framework requirement) → allowlist.
          const win = lines.slice(Math.max(0, i - 8), i + 4).join("\n");
          const nextAuthAdapter =
            /(PrismaAdapter|DrizzleAdapter|@auth\/|next-auth|AdapterAccount|linkAccount|account\.(provider|providerAccountId))/i.test(
              win,
            );
          // If the value is an auth/signature/query-string template (e.g.
          // `apiKey:${apiKey}&...`) it is in transit, NOT a token persisted to the DB → drop.
          const isAuthStringTemplate =
            /[&?]|authString|signature|\bhmac\b|basic\s|Authorization|header/i.test(
              tm ? tm[2] : "",
            );
          if (
            tm &&
            nearMutation &&
            !nextAuthAdapter &&
            !isAuthStringTemplate &&
            !ENCRYPTION_HINT.test(raw) &&
            // If the value is protected by an encryption or hash wrapper it is NOT plaintext.
            !VALUE_IS_PROTECTED.test(tm[2]) &&
            !NOT_STORED_VALUE.test(tm[2])
          ) {
            const key = `${file}:${i}:token`;
            if (!seen.has(key)) {
              seen.add(key);
              findings.push({
                ruleId: this.id,
                title: "Token or secret written to a plaintext database column",
                owasp: this.owasp,
                // A real plaintext-persist data flow (token → INSERT/UPDATE with no
                // encryption) → deterministic, a genuine finding.
                severity: "high",
                confidence: "certain",
                cwe: this.cwe,
                description:
                  "An OAuth/API token or a secret is stored in plaintext by a database write (insert/update/upsert), with no field-level encryption or hashing nearby. In a leak these tokens are directly usable.",
                evidence: [fileEvidence(file, i + 1, raw)],
                remediation:
                  "Store tokens and secrets encrypted (field-level encryption or a KMS), or keep only a hash and never the raw value.",
              });
            }
          }
        }
      }
    }
    return findings;
  },
};
