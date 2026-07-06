import type { Rule } from "./core/rule.js";

// A01 — Broken Access Control
import { apiRouteAuthMissing } from "./static/api-route-auth-missing.js";
import { idorDirectObject } from "./static/idor-direct-object.js";
import { supabaseServiceRole } from "./static/supabase-service-role.js";
// A02 — Cryptographic Failures
import { hardcodedSecrets } from "./static/hardcoded-secrets.js";
import { envCommitted } from "./static/env-committed.js";
import { nextPublicSecret } from "./static/next-public-secret.js";
import { weakHash } from "./static/weak-hash.js";
// A03 — Injection
import { sqlInjection } from "./static/sql-injection.js";
import { dangerousEval } from "./static/dangerous-eval.js";
// A04 — Insecure Design
import { missingRateLimit } from "./static/missing-rate-limit.js";
// A05 — Security Misconfiguration
import { securityHeadersConfig } from "./static/security-headers-config.js";
import { corsWildcard } from "./static/cors-wildcard.js";
// A07 — Identification & Authentication Failures
import { jwtWeakVerification } from "./static/jwt-weak-verification.js";
// A08 — Software & Data Integrity Failures
import { webhookSignature } from "./static/webhook-signature.js";
// A09 — Security Logging & Monitoring Failures
import { auditLogging } from "./static/audit-logging.js";
// A10 — SSRF
import { ssrf } from "./static/ssrf.js";
// A06 — deps
import { npmAudit } from "./deps/npm-audit.js";
// live
import { liveSecurityHeaders } from "./live/security-headers.js";
import { liveTransportSecurity } from "./live/transport-security.js";
import { liveExposedFiles } from "./live/exposed-files.js";
import { liveOpenEndpoints } from "./live/open-endpoints.js";
import { liveReflectedXss } from "./live/reflected-xss.js";
import { liveUserEnumeration } from "./live/user-enumeration.js";

export const staticRules: Rule[] = [
  apiRouteAuthMissing,
  idorDirectObject,
  supabaseServiceRole,
  hardcodedSecrets,
  envCommitted,
  nextPublicSecret,
  weakHash,
  sqlInjection,
  dangerousEval,
  missingRateLimit,
  securityHeadersConfig,
  corsWildcard,
  jwtWeakVerification,
  webhookSignature,
  auditLogging,
  ssrf,
];

export const depsRules: Rule[] = [npmAudit];

export const liveRules: Rule[] = [
  liveSecurityHeaders,
  liveTransportSecurity,
  liveExposedFiles,
  liveOpenEndpoints,
  liveReflectedXss,
  liveUserEnumeration,
];

export const allRules: Rule[] = [...staticRules, ...depsRules, ...liveRules];
