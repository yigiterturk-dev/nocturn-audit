import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A08 — no Subresource Integrity (SRI) on an external <script>.
 *
 * When a script loaded from a third-party CDN carries no `integrity` attribute,
 * a compromised or modified CDN can execute malicious code (supply chain).
 */

// A <script ... src="http(s)://..."> opening tag (line breaks inside the tag allowed).
const SCRIPT_TAG = /<script\b[^>]*\bsrc\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gis;
const HAS_INTEGRITY = /\bintegrity\s*=/i;
const LOCALHOST = /https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i;

const isMarkupFile = (file: string): boolean =>
  /\.(html?|tsx|jsx)$/.test(file.replace(/\\/g, "/"));

export const externalScriptSri: StaticRule = {
  id: "a08-external-script-no-sri",
  title: "Harici script'te SRI (integrity) yok",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "medium",
  cwe: "CWE-353",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (!isMarkupFile(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      const rx = new RegExp(SCRIPT_TAG.source, SCRIPT_TAG.flags);
      let m: RegExpExecArray | null;
      while ((m = rx.exec(content)) !== null) {
        const tag = m[0];
        if (HAS_INTEGRITY.test(tag)) continue;
        if (LOCALHOST.test(tag)) continue;
        const line = content.slice(0, m.index).split(/\r?\n/).length;
        findings.push({
          ruleId: this.id,
          title: this.title,
          owasp: this.owasp,
          severity: "medium",
          cwe: this.cwe,
          description:
            "A <script> loaded from a third-party origin declares no integrity (SRI) hash. If the CDN is compromised or the file is modified, the browser executes the malicious code without noticing the change.",
          evidence: [fileEvidence(file, line, tag.replace(/\s+/g, " ").slice(0, 200))],
          remediation:
            "Add integrity (sha384) and crossorigin='anonymous' to external scripts, and self-host critical dependencies where you can.",
          remediationCode:
            '<script src="https://cdn.example.com/lib.js"\n' +
            '        integrity="sha384-..." crossorigin="anonymous"></script>',
        });
      }
    }
    return findings;
  },
};
