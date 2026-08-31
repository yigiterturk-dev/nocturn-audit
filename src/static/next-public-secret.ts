import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A02 — a secret under NEXT_PUBLIC_ / VITE_.
 * These prefixes are inlined into the client bundle; variables named secret/service/private leak.
 */

const PUBLIC_SECRET =
  /\b(NEXT_PUBLIC_|VITE_)([A-Z0-9_]*?(SECRET|SERVICE_ROLE|PRIVATE|SERVICE_KEY|API_SECRET|CLIENT_SECRET|PASSWORD|TOKEN|STRIPE_SK|SK_LIVE|WEBHOOK_SECRET)[A-Z0-9_]*)/;

// tolerated: public keys that are meant to be published
const BENIGN =
  /(PUBLISHABLE|ANON_KEY|PUBLIC_KEY|CLERK_PUBLISHABLE|GA_|GTM_|SENTRY_DSN|MAPBOX|POSTHOG)/;

export const nextPublicSecret: StaticRule = {
  id: "a02-next-public-secret-leak",
  title: "Secret leaked to the client (NEXT_PUBLIC_ / VITE_)",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "critical",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  // A server-only secret under NEXT_PUBLIC_ → deterministic.
  confidence: "certain",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const matches = ctx.grep(PUBLIC_SECRET);
    for (const m of matches) {
      if (BENIGN.test(m.text)) continue;
      const key = `${m.file}:${m.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "critical",
        description:
          "Variables prefixed NEXT_PUBLIC_ or VITE_ are inlined into the client bundle. This name implies a secret (secret/service_role/private/token), which means it is shipped to the browser.",
        evidence: [fileEvidence(m.file, m.line, m.text)],
        remediation:
          "Drop the NEXT_PUBLIC_/VITE_ prefix from the secret and read it only on the server. Revoke and reissue the leaked key.",
      });
    }
    return findings;
  },
};
