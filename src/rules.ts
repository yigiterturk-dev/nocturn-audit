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
import { sqlIdentifierInjection } from "./static/sql-identifier-injection.js";
import { pathTraversal } from "./static/path-traversal.js";
import { redos } from "./static/redos.js";
import { prototypePollution } from "./static/prototype-pollution.js";
// A04 — Insecure Design
import { checkThenActUpsert } from "./static/check-then-act-upsert.js";
import { inmemoryRatelimitServerless } from "./static/inmemory-ratelimit-serverless.js";
import { missingRateLimit } from "./static/missing-rate-limit.js";
import { sqliteNoBusyTimeout } from "./static/sqlite-no-busy-timeout.js";
import { fkCascadeOff } from "./static/fk-cascade-off.js";
import { unguardedJsonParse } from "./static/unguarded-json-parse.js";
import { unboundedPaidLoop } from "./static/unbounded-paid-loop.js";
import { tarihUtcGunKaymasi } from "./static/tarih-utc-gun-kaymasi.js";
import { serverActionAuthMissing } from "./static/server-action-auth-missing.js";
import { yedekKanitiYok } from "./static/yedek-kaniti-yok.js";
// A05 — Security Misconfiguration
import { securityHeadersConfig } from "./static/security-headers-config.js";
import { corsWildcard } from "./static/cors-wildcard.js";
import { buildConfig } from "./static/build-config.js";
import { backupCruftTracked } from "./static/backup-cruft-tracked.js";
// A07 — Identification & Authentication Failures
import { jwtWeakVerification } from "./static/jwt-weak-verification.js";
import { spoofableClientIp } from "./static/spoofable-client-ip.js";
import { jwtAlgNone } from "./static/jwt-alg-none.js";
// A08 — Software & Data Integrity Failures
import { webhookSignature } from "./static/webhook-signature.js";
import { externalScriptSri } from "./static/external-script-sri.js";
import { testSchemaDivergence } from "./static/test-schema-divergence.js";
// A09 — Security Logging & Monitoring Failures
import { auditLogging } from "./static/audit-logging.js";
import { securityTxt } from "./static/security-txt.js";
import { swallowedDdlError } from "./static/swallowed-ddl-error.js";
// A10 — SSRF
import { ssrf } from "./static/ssrf.js";
// A06 — deps
import { npmAudit } from "./deps/npm-audit.js";
import { outdatedDeps } from "./deps/outdated-deps.js";
import { pipAudit } from "./deps/pip-audit.js";
// live
import { liveSecurityHeaders } from "./live/security-headers.js";
import { liveTransportSecurity } from "./live/transport-security.js";
import { liveExposedFiles } from "./live/exposed-files.js";
import { liveExposedSecrets } from "./live/exposed-secrets.js";
import { liveSslDomain } from "./live/ssl-domain.js";
import { liveOpenEndpoints } from "./live/open-endpoints.js";
import { liveReflectedXss } from "./live/reflected-xss.js";
import { liveUserEnumeration } from "./live/user-enumeration.js";
import { liveCorsMisconfig } from "./live/cors-misconfig.js";
import { liveHttpMethods } from "./live/http-methods.js";
import { liveDirectoryListing } from "./live/directory-listing.js";

// Integrity — the "the system says it is fine and it is not" family.
import { piiInRepo } from "./integrity/pii-in-repo.js";
import { sqlDialectLeftover } from "./integrity/sql-dialect-leftover.js";
import { piiInLogs } from "./integrity/pii-in-logs.js";
import { piiInGeneratedOutput } from "./integrity/pii-in-generated-output.js";
import { piiInCommitMessages } from "./integrity/pii-in-commit-messages.js";
import { pageApiAuthDivergence } from "./integrity/page-api-auth-divergence.js";
import { unboundSessionFallthrough } from "./integrity/unbound-session-fallthrough.js";
import { statusFromConfigNotProbe } from "./integrity/status-from-config-not-probe.js";
import { gateConditionTooBroad } from "./integrity/gate-condition-too-broad.js";
import { hardcodedStatus } from "./integrity/hardcoded-status.js";
import { handEnumeratedTestList } from "./integrity/hand-enumerated-test-list.js";
import { generatedFileHandEdited } from "./integrity/generated-file-hand-edited.js";
import { scopeHandEnumerated } from "./integrity/scope-hand-enumerated.js";
import { permissionAfterValidation } from "./integrity/permission-after-validation.js";
import { updateGuardWithoutDelete } from "./integrity/update-guard-without-delete.js";
import { sessionRevokeMissing } from "./integrity/session-revoke-missing.js";
import { backupWithoutRestoreRehearsal } from "./integrity/backup-without-restore-rehearsal.js";
import { alertTargetMissing } from "./integrity/alert-target-missing.js";
import { staticPageStrictCsp } from "./integrity/static-page-strict-csp.js";
import { contractTwoWriters } from "./integrity/contract-two-writers.js";
import { scanAfterWrite } from "./integrity/scan-after-write.js";
import { silentBudgetDenial } from "./integrity/silent-budget-denial.js";
import { icLinkAlakasizCapa } from "./integrity/ic-link-alakasiz-capa.js";
// live
import { liveHealthEndpoints } from "./live/health-endpoints.js";
import { livePageNonceCoverage } from "./live/page-nonce-coverage.js";

export const staticRules: Rule[] = [
  piiInRepo,
  sqlDialectLeftover,
  piiInLogs,
  piiInGeneratedOutput,
  piiInCommitMessages,
  pageApiAuthDivergence,
  unboundSessionFallthrough,
  statusFromConfigNotProbe,
  gateConditionTooBroad,
  hardcodedStatus,
  handEnumeratedTestList,
  generatedFileHandEdited,
  scopeHandEnumerated,
  permissionAfterValidation,
  updateGuardWithoutDelete,
  sessionRevokeMissing,
  backupWithoutRestoreRehearsal,
  alertTargetMissing,
  staticPageStrictCsp,
  contractTwoWriters,
  scanAfterWrite,
  silentBudgetDenial,
  icLinkAlakasizCapa,
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
  sqlIdentifierInjection,
  pathTraversal,
  redos,
  prototypePollution,
  dangerousEval,
  missingRateLimit,
  sqliteNoBusyTimeout,
  checkThenActUpsert,
  inmemoryRatelimitServerless,
  tarihUtcGunKaymasi,
  serverActionAuthMissing,
  yedekKanitiYok,
  fkCascadeOff,
  unguardedJsonParse,
  unboundedPaidLoop,
  securityHeadersConfig,
  corsWildcard,
  buildConfig,
  backupCruftTracked,
  jwtWeakVerification,
  spoofableClientIp,
  jwtAlgNone,
  webhookSignature,
  externalScriptSri,
  testSchemaDivergence,
  auditLogging,
  securityTxt,
  swallowedDdlError,
  ssrf,
];

export const depsRules: Rule[] = [npmAudit, pipAudit, outdatedDeps];

export const liveRules: Rule[] = [
  liveSecurityHeaders,
  liveTransportSecurity,
  liveExposedFiles,
  liveExposedSecrets,
  liveSslDomain,
  liveOpenEndpoints,
  liveReflectedXss,
  liveUserEnumeration,
  liveHealthEndpoints,
  liveCorsMisconfig,
  liveHttpMethods,
  liveDirectoryListing,
  livePageNonceCoverage,
];

export const allRules: Rule[] = [...staticRules, ...depsRules, ...liveRules];
