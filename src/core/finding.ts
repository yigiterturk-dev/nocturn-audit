import type { Severity } from "./severity.js";

/**
 * A finding's confidence (a backwards-compatible extra field):
 *  - "certain" → deterministic, verified (e.g. a committed .env, a plaintext sensitive column).
 *  - "likely"  → heuristic or pattern-based, needs manual verification (e.g. possible SQLi/SSRF).
 * Older consumers ignore the field.
 */
export type Confidence = "certain" | "likely";

/** OWASP Top 10 2021 kategorileri. */
export type OwaspCategory =
  | "A01:2021-Broken Access Control"
  | "A02:2021-Cryptographic Failures"
  | "A03:2021-Injection"
  | "A04:2021-Insecure Design"
  | "A05:2021-Security Misconfiguration"
  | "A06:2021-Vulnerable & Outdated Components"
  | "A07:2021-Identification & Authentication Failures"
  | "A08:2021-Software & Data Integrity Failures"
  | "A09:2021-Security Logging & Monitoring Failures"
  | "A10:2021-Server-Side Request Forgery";

/** A finding's evidence: either file:line or an HTTP request/response. */
export interface Evidence {
  kind: "file" | "http";
  /** kind === "file" */
  file?: string;
  line?: number;
  snippet?: string;
  /** kind === "http" */
  request?: string;
  response?: string;
}

/** A single security finding. */
export interface Finding {
  ruleId: string;
  title: string;
  owasp: OwaspCategory;
  severity: Severity;
  /** Description — why it is a risk. */
  description: string;
  /** Evidence — file:line or HTTP traffic. */
  evidence: Evidence[];
  /** Suggested fix. */
  remediation: string;
  /**
   * Related CWE id (e.g. "CWE-311"). Backwards-compatible, optional.
   * Older consumers ignore it.
   */
  cwe?: string;
  /**
   * A short remediation code sample where applicable. Backwards-compatible, optional.
   */
  remediationCode?: string;
  /**
   * The finding's confidence. Backwards-compatible, optional.
   * When absent, the rule's default `confidence` is used, else "likely" (assigned by the engine).
   * Older consumers ignore it.
   */
  confidence?: Confidence;
}

export function fileEvidence(
  file: string,
  line: number,
  snippet: string,
): Evidence {
  return { kind: "file", file, line, snippet: snippet.trim().slice(0, 240) };
}

export function httpEvidence(request: string, response: string): Evidence {
  return { kind: "http", request, response };
}
