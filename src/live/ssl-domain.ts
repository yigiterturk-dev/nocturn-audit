import tls from "node:tls";
import { lookup } from "node:dns/promises";
import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveContext, LiveRule } from "../core/rule.js";

/** Network primitives — mockable in tests (deterministic and offline). */
export interface SslDomainHooks {
  dnsLookup(host: string): Promise<unknown>;
  fetchCert(host: string): Promise<CertInfo>;
}

/**
 * A05 (live) — SSL certificate and domain health.
 *
 * The owned:true gate is enforced by the engine. Non-destructive: a single TLS
 * handshake, a DNS lookup and an HTTP redirect check. Certificate expiry is
 * deterministic → "certain". DNS and redirects are heuristic → "likely".
 */

export interface CertInfo {
  validTo?: string;
  error?: string;
}

/** Performs a single TLS handshake on port 443 and reads the peer certificate (valid_to). */
function fetchCert(host: string, timeoutMs = 10_000): Promise<CertInfo> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (info: CertInfo) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {
        /* yoksay */
      }
      resolve(info);
    };
    // rejectUnauthorized:false → so we can still READ AND JUDGE the certificate
    // when it is expired or mismatched (we make the decision ourselves).
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: false, timeout: timeoutMs },
      () => {
        const cert = socket.getPeerCertificate();
        finish({ validTo: cert?.valid_to });
      },
    );
    socket.on("timeout", () => finish({ error: "TLS handshake timed out" }));
    socket.on("error", (e) => finish({ error: e instanceof Error ? e.message : String(e) }));
  });
}

/** Extract the hostname from baseUrl. */
function hostnameOf(baseUrl: string): string | null {
  try {
    return new URL(baseUrl).hostname || null;
  } catch {
    return null;
  }
}

const RULE_ID = "a05-live-ssl-domain";
const RULE_OWASP = "A05:2021-Security Misconfiguration" as const;

const DEFAULT_HOOKS: SslDomainHooks = {
  dnsLookup: (host) => lookup(host),
  fetchCert: (host) => fetchCert(host),
};

/**
 * The rule body (with test hooks). `run` calls it with the real DNS/TLS
 * primitives; tests call it with mocks and verify without touching the network.
 */
export async function evaluateSslDomain(
  ctx: LiveContext,
  hooks: SslDomainHooks = DEFAULT_HOOKS,
): Promise<Finding[]> {
    const findings: Finding[] = [];
    const host = hostnameOf(ctx.baseUrl);
    if (!host) return findings;
    const isHttps = ctx.baseUrl.startsWith("https://");
    const self = { id: RULE_ID, owasp: RULE_OWASP };

    // --- 1) DNS resolution ---
    try {
      await hooks.dnsLookup(host);
    } catch {
      findings.push({
        ruleId: self.id,
        title: `DNS did not resolve: ${host}`,
        owasp: self.owasp,
        severity: "medium",
        confidence: "likely",
        description: `No DNS A/AAAA record resolved for ${host}. The domain may have expired, DNS may be misconfigured, or this may be a transient outage.`,
        evidence: [httpEvidence(`DNS lookup ${host}`, "NXDOMAIN / did not resolve")],
        remediation:
          "Confirm the domain registration is active and that the correct A/CNAME records exist at your DNS provider.",
      });
      // Without DNS, TLS and redirects are meaningless — return early.
      return findings;
    }

    // --- 1b) IS THE SITE SERVED OVER PLAIN HTTP? ---
    //
    // This rule used to check certificates on https addresses only; given an
    // http:// address it STAYED SILENT. So the tool said nothing at all about a
    // site served unencrypted — the live canary exposed it (one of ten live
    // rules never fired, and the reason was not "na" but blindness).
    //
    //
    // Note: the engine normalises the base URL by following an http→https
    // redirect. If we still arrive here with http, the site REALLY does not
    // redirect.
    if (!isHttps) {
      findings.push({
        ruleId: self.id,
        title: "Site is served over plain HTTP (no TLS)",
        owasp: self.owasp,
        severity: "high",
        confidence: "certain",
        description:
          `${host} does not redirect to https; traffic travels unencrypted. Session cookies, ` +
          "passwords and personal data can be read and modified at every network hop. " +
          "HSTS, Secure cookies and modern browser protections do not work at all without TLS.",
        evidence: [httpEvidence(`GET ${ctx.baseUrl}`, "scheme: http (no redirect)")],
        remediation:
          "Install a TLS certificate (Let's Encrypt or Caddy will do it automatically) and redirect http to " +
          "https with a 308, then add HSTS.",
      });
    }

    // --- 2) TLS certificate expiry (https only) ---
    if (isHttps) {
      const cert = await hooks.fetchCert(host);
      if (cert.validTo) {
        const expiry = new Date(cert.validTo).getTime();
        if (Number.isFinite(expiry)) {
          const days = Math.floor((expiry - Date.now()) / 86_400_000);
          if (days < 0) {
            findings.push({
              ruleId: self.id,
              title: `SSL certificate has EXPIRED: ${host}`,
              owasp: self.owasp,
              severity: "critical",
              confidence: "certain",
              cwe: "CWE-298",
              description: `The TLS certificate for ${host} expired ${Math.abs(days)} day(s) ago (valid_to: ${cert.validTo}). Visitors see a browser security warning.`,
              evidence: [httpEvidence(`TLS ${host}:443`, `valid_to: ${cert.validTo}`)],
              remediation:
                "Renew the certificate immediately and make sure automatic renewal (Let's Encrypt or your host) actually runs.",
            });
          } else if (days < 7) {
            findings.push({
              ruleId: self.id,
              title: `SSL certificate expires in ${days} day(s): ${host}`,
              owasp: self.owasp,
              severity: "critical",
              confidence: "certain",
              cwe: "CWE-298",
              description: `The TLS certificate for ${host} expires in ${days} day(s) (valid_to: ${cert.validTo}). If renewal fails the site becomes unreachable.`,
              evidence: [httpEvidence(`TLS ${host}:443`, `valid_to: ${cert.validTo}`)],
              remediation:
                "Trigger the renewal now, or verify that automatic renewal works.",
            });
          } else if (days < 30) {
            findings.push({
              ruleId: self.id,
              title: `SSL certificate expires in ${days} day(s): ${host}`,
              owasp: self.owasp,
              severity: "high",
              confidence: "certain",
              cwe: "CWE-298",
              description: `The TLS certificate for ${host} expires in ${days} day(s) (valid_to: ${cert.validTo}). Plan the renewal if it is not automatic.`,
              evidence: [httpEvidence(`TLS ${host}:443`, `valid_to: ${cert.validTo}`)],
              remediation: "Schedule the renewal, or verify that automatic renewal works.",
            });
          }
        }
      }
    }

    // --- 3) HTTP → HTTPS redirect and redirect chain length ---
    if (isHttps) {
      const httpProbe = await ctx.probe(`http://${host}/`);
      if (httpProbe.ok) {
        const loc = httpProbe.headers["location"] ?? "";
        const redirectsToHttps =
          httpProbe.status >= 300 &&
          httpProbe.status < 400 &&
          /^https:\/\//i.test(loc);
        if (httpProbe.status === 200) {
          // Plain HTTP returned 200 — there is no redirect to HTTPS.
          findings.push({
            ruleId: self.id,
            title: `HTTP does not redirect to HTTPS: ${host}`,
            owasp: self.owasp,
            severity: "medium",
            confidence: "likely",
            cwe: "CWE-319",
            description: `A request to http://${host}/ returned 200 without redirecting to HTTPS. Traffic can travel unencrypted (SSL stripping risk).`,
            evidence: [httpEvidence(httpProbe.requestLine, httpProbe.responseLine)],
            remediation:
              "Permanently redirect (301) every HTTP request to HTTPS, and add HSTS.",
          });
        } else if (httpProbe.status >= 300 && httpProbe.status < 400 && !redirectsToHttps) {
          findings.push({
            ruleId: self.id,
            title: `HTTP redirect does not target HTTPS: ${host}`,
            owasp: self.owasp,
            severity: "low",
            confidence: "likely",
            cwe: "CWE-319",
            description: `http://${host}/ redirects, but not to HTTPS (Location: ${loc || "?"}).`,
            evidence: [httpEvidence(httpProbe.requestLine, httpProbe.responseLine)],
            remediation: "Verify the HTTP → HTTPS 301 redirect.",
          });
        }
      }
    }

    // --- 4) Redirect chain length (via /) ---
    let current = "/";
    let hops = 0;
    const seen = new Set<string>();
    const chain: string[] = [];
    while (hops < 8) {
      const r = await ctx.probe(current);
      if (!r.ok) break;
      chain.push(`${r.status} ${r.url}`);
      if (r.status >= 300 && r.status < 400) {
        const loc = r.headers["location"];
        if (!loc || seen.has(loc)) break;
        seen.add(loc);
        current = loc;
        hops++;
      } else {
        break;
      }
    }
    if (hops >= 4) {
      findings.push({
        ruleId: self.id,
        title: `Long redirect chain (${hops} hops): ${host}`,
        owasp: self.owasp,
        severity: "low",
        confidence: "likely",
        description: `The root URL goes through ${hops} redirect hops. Long chains add latency and often signal a redirect loop or a misconfiguration.`,
        evidence: [httpEvidence(`GET ${ctx.baseUrl}/`, chain.join("\n"))],
        remediation:
          "Reduce the number of redirects; collapse www, HTTPS and locale redirects into a single hop.",
      });
    }

    return findings;
}

export const liveSslDomain: LiveRule = {
  id: RULE_ID,
  title: "Live: SSL certificate and domain health",
  owasp: RULE_OWASP,
  severity: "high",
  kind: "live",
  // Live probe: without an address, or without an answer, nothing can be measured.
  requires: ["live"],
  run(ctx): Promise<Finding[]> {
    return evaluateSslDomain(ctx);
  },
};
