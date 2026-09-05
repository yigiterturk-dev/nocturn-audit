import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A05 (live) — directory listing.
 *
 * Probes common asset/upload directories and looks for an "Index of /" listing
 * in the response. A listing exposes file names and paths that should stay
 * private.
 */

const DIRS = ["/uploads", "/files", "/static", "/assets", "/images", "/backup", "/logs", "/.git"];

export const liveDirectoryListing: LiveRule = {
  id: "a05-live-directory-listing",
  title: "Live: directory listing exposed",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "live",
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const dir of DIRS) {
      const res = await ctx.probe(dir);
      if (!res.ok || res.status >= 400) continue;
      const body = (res.bodySnippet ?? "").toLowerCase();
      if (/index of \/|directory listing|parent directory/.test(body)) {
        findings.push({
          ruleId: this.id,
          title: `Directory listing exposed at ${dir}`,
          owasp: this.owasp,
          severity: "medium",
          confidence: "certain",
          description: `GET ${dir} returns a directory index. File names and paths are exposed to anyone.`,
          evidence: [httpEvidence(res.requestLine, res.responseLine)],
          remediation: "Disable directory listing (Options -Indexes / autoindex off) and serve an index page.",
        });
        break;
      }
    }
    return findings;
  },
};
