import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A08 — the test schema was copied from production BY HAND (it drifts silently).
 *
 * When the test setup (conftest.py, a test bootstrap) repeats production's
 * CREATE TABLE by hand, that copy falls behind the moment the production schema
 * changes (a new column or table). The tests then run against an INCOMPLETE
 * schema and their PASSING proves nothing — tests that blow up with "no such
 * column" never exercise the real behaviour.
 *
 * Real case: a conftest wrote the schema for three tables by hand; production's
 * newer columns were missing and the upsert tests kept failing. It bit three
 * times in one month. The fix: have the test call production's own builder
 * (init_db / migrations) instead of copying the schema.
 *
 * This rule flags a TEST file (conftest / test_*) containing a SQL CREATE TABLE
 * literal when the project also has a production schema builder
 * (init_db/migrate/schema).
 */

const CREATE_TABLE = /CREATE\s+TABLE(\s+IF\s+NOT\s+EXISTS)?\s+\w+/i;

const isTestFile = (f: string) =>
  /(^|\/)(conftest|test_|_test|tests?\/|spec\/)/i.test(f.replace(/\\/g, "/")) ||
  /\.(test|spec)\.(py|js|ts)$/.test(f);

// Does the project have a production schema builder (which the test should call instead of copying)?
const SCHEMA_BUILDER =
  /(def\s+init_db|def\s+create_all|def\s+semayi_kur|def\s+tablo_kur|migrations?|alembic|CREATE\s+TABLE)/i;

export const testSchemaDivergence: StaticRule = {
  id: "a08-test-schema-divergence",
  title: "Test schema hand-copied from production (it drifts silently)",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "low",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];

    // Is there a CREATE TABLE or schema builder on the production (non-test) side?
    let prodHasSchema = false;
    for (const file of ctx.files) {
      if (isTestFile(file)) continue;
      const c = ctx.read(file);
      if (c && SCHEMA_BUILDER.test(c)) {
        prodHasSchema = true;
        break;
      }
    }
    if (!prodHasSchema) return findings; // with no schema at all this does not apply

    const flagged = new Set<string>();
    for (const file of ctx.files) {
      if (!isTestFile(file)) continue;
      if (flagged.has(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      // Does the test file build its own CREATE TABLE?
      const m = content.split(/\r?\n/).findIndex((l) => CREATE_TABLE.test(l));
      if (m < 0) continue;
      flagged.add(file);

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "low",
        description:
          `${file} is a test file that contains a literal SQL CREATE TABLE ` +
          `(line ${m + 1}). When the production schema changes this copy falls behind, ` +
          `the tests run against an INCOMPLETE schema, and passing proves nothing.`,
        evidence: [fileEvidence(file, m + 1, "CREATE TABLE inside a test")],
        remediation:
          "Have the test call production's own schema builder instead of writing the schema " +
          "by hand (init_db, migrations). One source of truth means test and production " +
          "can never drift apart. Remove the schema copies from the fixtures.",
      });
    }
    return findings;
  },
};
