import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A07 — the closing condition is BROADER than the gate.
 *
 * A setup path or a backup entrance should close once it is "no longer needed".
 * The closing condition tends to be written as "is there any account at all?" —
 * but when the gate concerns only one KIND of account, creating an account of
 * another kind closes that gate unfairly.
 *
 * Real case: a shared password was a STAFF setup path, and its closing condition
 * was "does any login credential exist". An operator who invited a TENANT before
 * creating their own account was locked out of the panel completely: the shared
 * password was now rejected, they had no account of their own, and there was no
 * way back in.
 *
 * The rule looks for this: the records carry a KIND distinction (subjectKind,
 * role, type), the code filters by it elsewhere, but the gate decision rests on
 * an unfiltered "does any exist" helper.
 */

/** Helpers that ask about existence without filtering. */
const GENIS_KONTROL =
  /\b(has(Any|Some)\w*|any\w*Exists|\w*Exists|count\w*)\s*\(\s*\)/;

/** Gate / setup decision context. */
const KAPI_BAGLAMI =
  /(gate|kapı|kapi|bootstrap|kurulum|setup|fallback|shared|ortak|legacy|initial)/i;

/** Field names that carry a kind distinction. */
const TUR_ALANI = /\b(subjectKind|subject_kind|kind|type|role|rol|category|tur)\b/;

export const gateConditionTooBroad: StaticRule = {
  id: "int-gate-condition-too-broad",
  title: "The closing condition is broader than the gate; an unrelated record closes it",
  owasp: "A07:2021-Identification & Authentication Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx: StaticContext): Finding[] {
    // Does the project have a KIND distinction at all? Without one, "too broad" has no meaning.
    const turKullanimi = ctx.grep(TUR_ALANI).filter((m) => !/\.(test|spec)\./.test(m.file));
    if (turKullanimi.length < 2) return [];

    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.(ts|js|mjs|cjs)$/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      // If the file PATH points at a gate, that alone is enough.
      const pathIsGate = KAPI_BAGLAMI.test(file);
      if (!pathIsGate && !KAPI_BAGLAMI.test(content)) continue;

      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        const genis = line.match(GENIS_KONTROL);
        if (!genis) continue;
        // Decision context: does this value determine a gate?
        // The window check is only needed when the file path does NOT point at a gate.
        //
        // The engine blanks out comments (for precision) and the gate context is
        // often explained in exactly those comments. When the path says
        // `.../gate/...`, demanding the context again from the window would
        // etmek olurdu.
        if (!pathIsGate) {
          const pencere = lines.slice(Math.max(0, i - 3), i + 6).join("\n");
          if (!KAPI_BAGLAMI.test(pencere)) continue;
        }
        // If there is a kind filter on the same line, the condition is already narrow.
        if (TUR_ALANI.test(line)) continue;

        // Does the helper itself filter? Look at its definition.
        const ad = genis[1];
        const tanim = content.match(new RegExp(`function\\s+${ad}\\b[\\s\\S]{0,400}`))
          || ctx.grep(new RegExp(`function\\s+${ad}\\b`))
            .map((m) => (ctx.read(m.file) || "").slice(
              (ctx.read(m.file) || "").indexOf(`function ${ad}`), 400 + (ctx.read(m.file) || "").indexOf(`function ${ad}`)))[0];
        if (tanim && TUR_ALANI.test(String(tanim))) continue;

        findings.push({
          ruleId: "int-gate-condition-too-broad",
          title: "The closing condition is broader than the gate; an unrelated record closes it",
          owasp: "A07:2021-Identification & Authentication Failures",
          severity: "high",
          confidence: "likely",
          description:
            `\`${file}:${i + 1}\` makes a gate decision with \`${ad}()\`, and that helper does not ` +
            "filter by record TYPE. The project does distinguish types (subjectKind/role/type), so this " +
            "gate probably concerns only one of them. When a record of another type appears, the gate " +
            "closes unfairly — and whoever needed it has no way back in.",
          evidence: [fileEvidence(file, i + 1, line.trim().slice(0, 140))],
          remediation:
            `Replace \`${ad}()\` with a helper that filters by type (e.g. hasStaffCredential). ` +
            "Then test exactly this scenario: while the person who needs the gate has not created their " +
            "own account yet, does creating a record of another type still let them in?",
        });
        break;
      }
    }
    return findings;
  },
};
