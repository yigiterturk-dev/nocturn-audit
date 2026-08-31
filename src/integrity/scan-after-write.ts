import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A08 — malware scanning happens AFTER the file is written.
 *
 * Writing a malicious file to storage first and deleting it afterwards leaves a
 * window in which someone can download it. The scan belongs before the write.
 */
// Real file/object WRITE sinks. CAREFUL: the Express route method
// `app.put('/api/...')` is NOT a file write (one server.ts had 20+ app.put
// routes → all of them FPs). The distinction: an Express route's first argument
// is a STRING ROUTE ('/...'); an object write (driver.put(key, bytes)) is not.
// `\.put(` counts as a write only when the first argument is NOT a '/...' route string.
const YAZMA = /\b(upload|writeFile|writeFileSync|createWriteStream|putObject)\s*\(|\.save\s*\(|multer\s*\(|\.put\s*\(\s*(?!['"`]\/)/;
// MALWARE scanning. CAREFUL: bare `scan(` is NOT included — far too broad (it
// matched project scans, code scans, database scans; in a tool that IS a scanner
// there is a scan() everywhere → FPs). Malware/virus-specific verbs: scanFile/
// scanUpload/scanDocument/virusScan/clamav/virusTotal...
const SCAN = /\b(scanFile|scanUpload|scanDocument|scanForVirus|virusScan|avScan|clamav|clamd|clamscan|virusTotal|malwareScan|antivirus)\w*\s*\(/i;

export const scanAfterWrite: StaticRule = {
  id: "int-scan-after-write",
  title: "Malware scanning happens after the file is written",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!/\.(ts|js|mjs)$/.test(file) || /\.(test|spec)\./.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      if (!SCAN.test(content) || !YAZMA.test(content)) continue;

      const yazma = content.search(YAZMA);
      const scan = content.search(SCAN);
      if (scan < yazma) continue;

      findings.push({
        ruleId: "int-scan-after-write",
        title: "Malware scanning happens after the file is written",
        owasp: "A08:2021-Software & Data Integrity Failures",
        severity: "high",
        confidence: "likely",
        description:
          `\`${file}\` scans the file after writing it to storage. A malicious file stays downloadable ` +
          "until it is deleted.",
        evidence: [fileEvidence(file, content.slice(0, yazma).split("\n").length, "write precedes scan")],
        remediation: "Scan before writing, and never write bytes that did not come back clean.",
      });
    }
    return findings;
  },
};
