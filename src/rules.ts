import type { Rule } from "./core/rule.js";

// A01 — Broken Access Control
import { apiRouteAuthMissing } from "./static/api-route-auth-missing.js";
import { idorDirectObject } from "./static/idor-direct-object.js";
import { supabaseServiceRole } from "./static/supabase-service-role.js";
import { missingRls } from "./static/missing-rls.js";
import { openRedirect } from "./static/open-redirect.js";
import { csrfMissing } from "./static/csrf-missing.js";
import { massAssignment } from "./static/mass-assignment.js";
// A02 — Cryptographic Failures
import { hardcodedSecrets } from "./static/hardcoded-secrets.js";
import { envCommitted } from "./static/env-committed.js";
import { nextPublicSecret } from "./static/next-public-secret.js";
import { weakHash } from "./static/weak-hash.js";
import { sensitiveDataPlaintext } from "./static/sensitive-data-plaintext.js";
import { secretsGitHistory } from "./static/secrets-git-history.js";
import { kvkkSpecialCategory } from "./static/kvkk-special-category.js";
// A03 — Injection
import { sqlInjection } from "./static/sql-injection.js";
import { dangerousEval } from "./static/dangerous-eval.js";
// A04 — Insecure Design
import { missingRateLimit } from "./static/missing-rate-limit.js";
// A05 — Security Misconfiguration
import { securityHeadersConfig } from "./static/security-headers-config.js";
import { corsWildcard } from "./static/cors-wildcard.js";
import { buildConfig } from "./static/build-config.js";
// A07 — Identification & Authentication Failures
import { jwtWeakVerification } from "./static/jwt-weak-verification.js";
// A08 — Software & Data Integrity Failures
import { webhookSignature } from "./static/webhook-signature.js";
import { externalScriptSri } from "./static/external-script-sri.js";
// A09 — Security Logging & Monitoring Failures
import { auditLogging } from "./static/audit-logging.js";
import { securityTxt } from "./static/security-txt.js";
// A10 — SSRF
import { ssrf } from "./static/ssrf.js";
// A06 — deps
import { npmAudit } from "./deps/npm-audit.js";
import { outdatedDeps } from "./deps/outdated-deps.js";
// live
import { liveSecurityHeaders } from "./live/security-headers.js";
import { liveTransportSecurity } from "./live/transport-security.js";
import { liveExposedFiles } from "./live/exposed-files.js";
import { liveExposedSecrets } from "./live/exposed-secrets.js";
import { liveSslDomain } from "./live/ssl-domain.js";
import { liveOpenEndpoints } from "./live/open-endpoints.js";
import { liveReflectedXss } from "./live/reflected-xss.js";
import { liveUserEnumeration } from "./live/user-enumeration.js";

export const staticRules: Rule[] = [
  apiRouteAuthMissing,
  idorDirectObject,
  supabaseServiceRole,
  missingRls,
  openRedirect,
  csrfMissing,
  massAssignment,
  hardcodedSecrets,
  envCommitted,
  nextPublicSecret,
  weakHash,
  sensitiveDataPlaintext,
  secretsGitHistory,
  kvkkSpecialCategory,
  sqlInjection,
  dangerousEval,
  missingRateLimit,
  securityHeadersConfig,
  corsWildcard,
  buildConfig,
  jwtWeakVerification,
  webhookSignature,
  externalScriptSri,
  auditLogging,
  securityTxt,
  ssrf,
];

export const depsRules: Rule[] = [npmAudit, outdatedDeps];

export const liveRules: Rule[] = [
  liveSecurityHeaders,
  liveTransportSecurity,
  liveExposedFiles,
  liveExposedSecrets,
  liveSslDomain,
  liveOpenEndpoints,
  liveReflectedXss,
  liveUserEnumeration,
];

export const allRules: Rule[] = [...staticRules, ...depsRules, ...liveRules];
