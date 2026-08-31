import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A08 — a one-sided immutability guard: UPDATE blocked, DELETE allowed.
 *
 * The claim "this record cannot be changed" is untested unless update and delete
 * were tested SEPARATELY. In a system where you cannot correct a record but can
 * destroy it, the destroyed record leaves no trace behind — the harshest form of
 * change is the least guarded one.
 */
const TRIGGER =
  /(?:CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER|CREATE\s+POLICY)\s+(\w+)[\s\S]{0,200}?\b(BEFORE|AFTER|FOR)\s+([A-Z ]*?)\s+ON\s+"?(\w+)"?/gi;

export const updateGuardWithoutDelete: StaticRule = {
  id: "int-update-guard-without-delete",
  title: "One-sided immutability guard: updates blocked, deletes allowed",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.sql$/.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      // Only REJECTING triggers count.
      //
      // Not every `BEFORE UPDATE` is an immutability guard — in Postgres the most
      // common trigger is an `updated_at` timestamp, and it forbids nothing. The
      // rule did not make that distinction and produced a "deletes are open"
      // finding for every project with an updated_at trigger.
      const reddeden = (ad: string): boolean => {
        if (/(no_(update|delete)|immutable|append_only|readonly|reddet|kilit|frozen|lock)/i.test(ad)) return true;
        // Does the function the trigger calls actually RAISE?
        const fn = content.match(new RegExp(`FUNCTION\\s+(\\w+)\\s*\\(\\)[^;]*?${ad}`, "i"))
          || content.match(new RegExp(`${ad}[\\s\\S]{0,200}?EXECUTE\\s+(?:PROCEDURE|FUNCTION)\\s+(\\w+)`, "i"));
        if (!fn) return false;
        // The body lives BETWEEN `AS $$ ... $$`. The first version matched lazily
        // up to `$$`, so it stopped at the OPENING `$$` and never read the body —
        // every guard that did raise was counted as "not rejecting".
        const body = content.match(
          new RegExp(`FUNCTION\\s+${fn[1]}\\s*\\([^)]*\\)[\\s\\S]{0,200}?AS\\s+\\$\\$([\\s\\S]{0,2000}?)\\$\\$`, "i"),
        );
        return Boolean(body && /RAISE\s+EXCEPTION/i.test(body[1]));
      };

      const updateli = new Set<string>();
      const deleteli = new Set<string>();
      for (const m of content.matchAll(TRIGGER)) {
        const olaylar = (m[3] || "").toUpperCase();
        const ad = m[1];
        const tablo = m[4];
        if (!reddeden(ad)) continue;
        if (/UPDATE/.test(olaylar)) updateli.add(tablo);
        if (/DELETE/.test(olaylar)) deleteli.add(tablo);
      }

      const acik = [...updateli].filter((t) => !deleteli.has(t));
      if (!acik.length) continue;

      findings.push({
        ruleId: "int-update-guard-without-delete",
        title: "One-sided immutability guard: updates blocked, deletes allowed",
        owasp: "A08:2021-Software & Data Integrity Failures",
        severity: "high",
        confidence: "likely",
        description:
          `In \`${file}\`, ${acik.length} table(s) have an UPDATE trigger but no DELETE trigger: ` +
          `${acik.slice(0, 8).join(", ")}. A record cannot be corrected, but it can be erased.`,
        evidence: [fileEvidence(file, 1, acik.slice(0, 5).join(", "))],
        remediation:
          "Write the DELETE counterpart of every immutability trigger. Keep a correction path open " +
          "through reversing entries — the goal is to prevent untraceable corrections, not corrections.",
      });
    }
    return findings;
  },
};
