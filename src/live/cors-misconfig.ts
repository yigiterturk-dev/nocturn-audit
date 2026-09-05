import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A05 (live) — CORS misconfiguration.
 *
 * Sends a request with a foreign Origin header and checks whether the server
 * reflects it (Access-Control-Allow-Origin: <origin>) or allows `*` together
 * with credentials. Both let a malicious site read the response.
 */

export const liveCorsMisconfig: LiveRule = {
  id: "a05-live-cors-misconfig",
  title: "Live: CORS misconfiguration",
  owasp: "A05:2021-Security Misconfiguration",
  severity: "medium",
  kind: "live",
  requires: ["live"],
  async run(ctx): Promise<Finding[]> {
    const evil = "https://evil.example";
    const res = await ctx.probe("/", {
      headers: { Origin: evil },
    });
    if (!res.ok) return [];
    const acao = res.headers["access-control-allow-origin"];
    const acac = res.headers["access-control-allow-credentials"];
    if (!acao) return [];

    const reflects = acao.trim() === evil;
    const wildcard = acao.trim() === "*";
    const withCreds = acac?.toLowerCase() === "true";

    if (reflects || (wildcard && withCreds)) {
      return [
        {
          ruleId: this.id,
          title: "CORS allows a foreign origin to read responses",
          owasp: this.owasp,
          severity: "high",
          confidence: "certain",
          description: reflects
            ? `The server reflects the Origin header (Access-Control-Allow-Origin: ${acao}). Any site can read the response.`
            : "Access-Control-Allow-Origin: * is combined with Access-Control-Allow-Credentials: true, which lets any site read authenticated responses.",
          evidence: [httpEvidence(res.requestLine, res.responseLine)],
          remediation:
            "Restrict Access-Control-Allow-Origin to a fixed allowlist of trusted origins and never pair '*' with credentials.",
        },
      ];
    }
    return [];
  },
};
