import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A02 — Hassas veri şifresiz (plaintext) saklanıyor.
 *
 * Prisma / Drizzle / ham SQL şemalarında ve migration'larda; ayrıca kod içindeki
 * DB yazma çağrılarında; TC kimlik, SSN, pasaport, kredi kartı/CVV, IBAN, sağlık/tıbbi,
 * OAuth/API token, gizli anahtar gibi hassas alanların `text`/`varchar`/`String` gibi
 * düz metin tiplerinde, alan-bazlı şifreleme sarmalayıcısı olmadan tutulduğunu yakalar.
 */

// Hassas alan adları (kolon/field/DB adı). \b sınırlarıyla dar tutuldu.
const SENSITIVE_NAME =
  /\b(tc[_-]?kimlik(?:[_-]?no)?|tckn|kimlik[_-]?no|ssn|social[_-]?security(?:[_-]?number)?|passport(?:[_-]?no)?|pasaport|credit[_-]?card|card[_-]?number|card[_-]?no|cardnum|cc[_-]?number|cvv|cvc|iban|health|medical|saglik|sağlık|hasta[_-]?(?:no|kayit)|diagnos(?:is|e)|tani|tanı|biometric|biyometrik|oauth[_-]?token|refresh[_-]?token|access[_-]?token|api[_-]?key|secret[_-]?key|private[_-]?key)\b/i;

// Düz metin tipleri (SQL + Prisma + Drizzle).
const PLAINTEXT_TYPE =
  /\b(text|varchar|char|citext|nvarchar|longtext|mediumtext|string)\b|\btext\s*\(|\bvarchar\s*\(|\bchar\s*\(/i;

// Şifreleme/koruma göstergeleri → bu satır güvenli sayılır.
const ENCRYPTION_HINT =
  /(bytea|pgp_sym_encrypt|pgp_pub_encrypt|pgcrypto|\bencrypt\b|encrypted|ciphertext|cipher|\bvault\b|EncryptedField|@Encrypted|@encrypted|crypto\.|createCipher|libsodium|sodium|kms|hashed|bcrypt|argon2|scrypt|\.hash\b)/i;

// Kod tarafı: DB'ye yazma çağrıları.
const DB_MUTATION =
  /\.(insert|create|createMany|update|updateMany|upsert|values|set|save)\s*\(|INSERT\s+INTO|UPDATE\s+\w+\s+SET/i;

// Kod tarafı: token/secret bir DB objesine düz atanıyor.
const TOKEN_PROP =
  /\b(access[_-]?token|refresh[_-]?token|oauth[_-]?token|api[_-]?key|apiKey|secret[_-]?key|client[_-]?secret)\s*:\s*([^,\n}]+)/i;

// Tip annotasyonu / env okuma / placeholder → gerçek saklama değil.
const NOT_STORED_VALUE =
  /^\s*(string|number|boolean|any|unknown|String|Boolean|Prisma\.|z\.|process\.env|import\.meta|["'`]?<)/;

const DB_MUTATION_SINK =
  /\.(insert|create|createMany|update|updateMany|upsert|values|save)\s*\(/i;

// Otomatik üretilmiş / tip tanımı dosyaları → atla.
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
  title: "Hassas alan şifresiz saklanıyor",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  cwe: "CWE-311",
  kind: "static",
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (isGenerated(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const schema = isSchemaFile(file);
      const fileHasMutation = DB_MUTATION.test(content);
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (ENCRYPTION_HINT.test(raw)) continue;

        // (A) Şema/migration: hassas isimli düz-metin kolon
        if (
          (schema || /\.(ts|js)$/.test(file)) &&
          SENSITIVE_NAME.test(raw) &&
          PLAINTEXT_TYPE.test(raw) &&
          looksLikeColumnDef(raw)
        ) {
          const key = `${file}:${i}:col`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              ruleId: this.id,
              title: this.title,
              owasp: this.owasp,
              severity: "high",
              cwe: this.cwe,
              description:
                "Hassas bir alan (kimlik/SSN/kart/CVV/IBAN/sağlık/token vb.) düz metin bir kolon tipinde (text/varchar/String), alan-bazlı şifreleme olmadan saklanıyor. Veritabanı yedeği veya sızıntısında bu veriler doğrudan okunur.",
              evidence: [fileEvidence(file, i + 1, raw)],
              remediation:
                "Alanı uygulama tarafında şifreleyip saklayın veya pgcrypto (pgp_sym_encrypt) ile şifreli tutun; kolonu bytea yapın. Kart verisi için mümkünse tokenizasyon/PCI-DSS uyumlu sağlayıcı kullanın.",
              remediationCode:
                "-- pgcrypto ile alan-bazlı şifreleme\n" +
                "-- INSERT: pgp_sym_encrypt($1, current_setting('app.enc_key'))\n" +
                "-- SELECT: pgp_sym_decrypt(col, current_setting('app.enc_key'))\n" +
                "ALTER TABLE t ALTER COLUMN sensitive_col TYPE bytea USING pgp_sym_encrypt(sensitive_col, :key);",
            });
          }
        }

        // (B) Kod tarafı: token/secret DB objesine düz atanıyor.
        // FP azalt: yakınında (aynı ya da önceki 4 satır) bir DB mutation sink olsun,
        // ve değer bir tip/env/placeholder olmasın.
        if (fileHasMutation && /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file)) {
          const tm = TOKEN_PROP.exec(raw);
          const nearMutation =
            DB_MUTATION_SINK.test(raw) ||
            lines.slice(Math.max(0, i - 4), i).some((l) => DB_MUTATION_SINK.test(l));
          if (
            tm &&
            nearMutation &&
            !ENCRYPTION_HINT.test(raw) &&
            !NOT_STORED_VALUE.test(tm[2])
          ) {
            const key = `${file}:${i}:token`;
            if (!seen.has(key)) {
              seen.add(key);
              findings.push({
                ruleId: this.id,
                title: "Token/secret düz metin DB kolonuna yazılıyor",
                owasp: this.owasp,
                severity: "medium",
                cwe: this.cwe,
                description:
                  "OAuth/API token ya da secret, bir DB yazma çağrısında (insert/update/upsert) düz metin olarak saklanıyor. Sızıntıda bu token'lar doğrudan kullanılabilir.",
                evidence: [fileEvidence(file, i + 1, raw)],
                remediation:
                  "Token/secret'leri şifreleyerek saklayın (alan-bazlı şifreleme / KMS) veya yalnızca hash'ini tutup ham değeri saklamayın.",
              });
            }
          }
        }
      }
    }
    return findings;
  },
};
