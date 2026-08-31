import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A01 — mass assignment.
 *
 * User input (req.body / req.json() / params) spread or passed straight into a
 * database create/update call, with no validation and no field selection. An
 * attacker can set unexpected fields (isAdmin, role, balance) to escalate privileges.
 */

// `new X(...)` MAY be a model constructor, but most built-ins are not.
// In one run, the line reported as "mass assignment" in two projects was
// `res.json({ ...report, generatedAt: new Date()... })`: what triggered the
// sink was `new Date(`, and what was mistaken for input was a report the server
// had generated itself. Nothing was written to a database at all.
const YERLESIK_KURUCU =
  /^(Date|Error|TypeError|RangeError|URL|URLSearchParams|Response|Request|Headers|FormData|Map|Set|WeakMap|WeakSet|RegExp|Promise|Array|Object|Blob|Buffer|TextEncoder|TextDecoder|AbortController|Intl|Function|Proxy|ReadableStream|WritableStream)$/;

const MUTATION_SINK =
  /\.(create|createMany|update|updateMany|upsert|insert|save)\s*\(|\.values\s*\(|new\s+[A-Z]\w*\s*\(/;

/** If the only sink on the line is a built-in constructor like `new Date(...)`, it is not a DB write. */
function sadeceYerlesikKurucu(raw: string): boolean {
  if (/\.(create|createMany|update|updateMany|upsert|insert|save)\s*\(|\.values\s*\(/.test(raw))
    return false;
  const kurucular = [...raw.matchAll(/new\s+([A-Z]\w*)\s*\(/g)].map((m) => m[1]);
  return kurucular.length > 0 && kurucular.every((k) => YERLESIK_KURUCU.test(k));
}

/**
 * Does this line build a RESPONSE? `res.json({ ...x })` sends to the client, it
 * does not write to the database. A spread here is not privilege escalation but
 * at most excessive data exposure — a different rule's job (a01-excessive-data-exposure).
 */
const CEVAP_SINK =
  /\bres\.(json|send|end)\s*\(|\bres\.status\s*\([^)]*\)\s*\.(json|send)\s*\(|\b(?:Next)?Response\.json\s*\(|\bnew\s+Response\s*\(/;

// Raw user input expressions.
const RAW_INPUT_SRC =
  /req\.body|request\.body|req\.query|req\.params|await\s+req\.json\(\)|await\s+req\.formData\(\)|await\s+request\.formData\(\)/;

/** Is the raw input ITSELF assigned to the variable (rather than passed as an argument)? */
const RAW_INPUT_ASSIGNMENT =
  /^\s*(?:await\s+)?(?:req\.body|request\.body|req\.query|req\.params|req\.json\(\)|request\.json\(\)|req\.formData\(\)|request\.formData\(\))(?![\w$])/;

/**
 * Wrappers that CARRY the input without SELECTING its contents.
 *
 * `const form = await req.formData(); const kayit = Object.fromEntries(form);`
 * — `record` still carries every field the user wrote. The taint used to
 * disappear one step later, and the canary caught it: mass assignment through a
 * form body had become invisible. Calls that SELECT fields (pick/parse/omit)
 * cut the taint; ones that only reshape do not.
 */
const GECIRGEN_SARMALAYICI =
  /^\s*(?:await\s+)?(?:Object\.fromEntries|Object\.assign|structuredClone|JSON\.parse|\{\s*\.\.\.)\s*\(?/;

const isServerFile = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return /\.(ts|js|mjs|cjs)$/.test(f) && !/\.d\.ts$/.test(f);
};


/**
 * Does `rhs` REALLY carry the variable `v`?
 *
 * `\b${v}\b` is not enough, and it is dangerous: a short variable name like `id`
 * also matches the PROPERTY name in `reviewer?.id`. That is exactly what
 * happened in one project — `id`, tainted by `req.params.id`, matched the `.id`
 * property of an unrelated object and produced 10 false mass-assignment findings.
 *
 * Carrying happens two ways: a spread (`{ ...v }`) or an argument to a wrapper
 * (`Object.fromEntries(v)`). In both, `v` is an identifier in its own right and
 * NOT a property name — it must not be preceded by a dot.
 */
function tasiyorMu(rhs: string, v: string): boolean {
  const kacir = v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // CAREFUL: no lookbehind here. The `...` operator's own dots make it look
  // "preceded by a dot", so `(?<![.])` always fails — which is what happened in
  // the first version, and the real two-step taint disappeared. The `...` prefix
  // already guarantees the expression is a spread source, not a property name.
  const yayilim = new RegExp(`\\.\\.\\.\\s*${kacir}(?![\\w$])`);
  const arguman = new RegExp(`\\(\\s*(?:\\{\\s*\\}\\s*,\\s*)?(?<![.\\w$])${kacir}(?![\\w$])\\s*[,)]`);
  return yayilim.test(rhs) || arguman.test(rhs);
}

export const massAssignment: StaticRule = {
  id: "a01-mass-assignment",
  title: "Mass assignment (unvalidated input spread into the database)",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  cwe: "CWE-915",
  kind: "static",
  // The rule's own code filters by JS/TS extension — in a Python or Go project it
  // can look at no file at all. Undeclared, it would return `[]` and read as "clean".
  requires: ["js"],
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (!isServerFile(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);

      // tainted: variables coming from raw input
      const tainted = new Set<string>();
      // validated: variables that passed schema validation → safe
      const validated = new Set<string>();
      for (const raw of lines) {
        const dm = /\b(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*([^;]+)/.exec(raw);
        if (!dm) {
          // destructuring: const { a } = schema.parse(...)
          const pm = /\b(?:const|let|var)\s*\{[^}]*\}\s*=\s*([^;]+)/.exec(raw);
          if (pm && /\.(safe)?parse\s*\(|\.validate(?:Sync|Async)?\s*\(|pick\s*\(/.test(pm[1])) {
            // destructured fields are already selected → not tainted
          }
          continue;
        }
        const name = dm[1];
        const rhs = dm[2];
        if (/\.(safe)?parse\s*\(|\.validate(?:Sync|Async)?\s*\(|zod|joi\.|yup\./.test(rhs)) {
          validated.add(name);
        } else if (
          GECIRGEN_SARMALAYICI.test(rhs) &&
          [...tainted].some((v) => tasiyorMu(rhs, v))
        ) {
          // A pass-through wrapper: the shape changed, the contents did not → taint persists.
          tainted.add(name);
        } else if (RAW_INPUT_ASSIGNMENT.test(rhs)) {
          // CAREFUL: "contains" is not enough. `const r = await report(req.params.id)`
          // is NOT raw input — it is an object the server produced. The taint exists
          // only when the input ITSELF is assigned: `= req.body`, `= await req.json()`.
          tainted.add(name);
        }
      }

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!MUTATION_SINK.test(raw)) continue;

        // Skip when validation already happened (a .parse on the line)
        if (/\.(safe)?parse\s*\(/.test(raw)) continue;
        // Building a response is not a database write — but if the same line also
        // contains a real DB sink (a handler squeezed onto one line), keep the finding.
        const gercekDbSink =
          /\.(create|createMany|update|updateMany|upsert|insert|save)\s*\(|\.values\s*\(/.test(
            raw,
          );
        if (CEVAP_SINK.test(raw) && !gercekDbSink) continue;
        // If the only sink is a built-in constructor like `new Date(...)`, it is not a DB write.
        if (sadeceYerlesikKurucu(raw)) continue;

        // (a) raw input directly: data: req.body | ...req.body | (req.body) | values(req.body)
        const directRaw =
          new RegExp(
            `(\\.\\.\\.\\s*(?:${RAW_INPUT_SRC.source})|` +
              `data\\s*:\\s*(?:${RAW_INPUT_SRC.source})|` +
              `values\\s*\\(\\s*(?:${RAW_INPUT_SRC.source})|` +
              `\\(\\s*(?:${RAW_INPUT_SRC.source})\\s*\\))`,
          ).test(raw);

        // (b) a tainted variable is spread or passed (unless validated)
        let taintedName = false;
        for (const v of tainted) {
          if (validated.has(v)) continue;
          if (
            new RegExp(`\\.\\.\\.\\s*${v}\\b|data\\s*:\\s*${v}\\b|values\\s*\\(\\s*${v}\\b`).test(raw)
          ) {
            taintedName = true;
            break;
          }
        }

        if (directRaw || taintedName) {
          findings.push({
            ruleId: this.id,
            title: this.title,
            owasp: this.owasp,
            severity: "high",
            cwe: this.cwe,
            description:
              "User input (req.body / req.json()) is passed straight into a database create/update call with no field selection or validation. An attacker can set unexpected columns (role, isAdmin, ownerId, balance) to escalate privileges or corrupt data.",
            evidence: [fileEvidence(file, i + 1, raw)],
            remediation:
              "Validate the input with a schema (zod/yup/joi) and pick only the allowed fields. Never spread the raw object into the ORM.",
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
