import type { Severity } from "./severity.js";

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

/** Bir bulgunun kanıtı: ya dosya:satır ya da HTTP istek/yanıt. */
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

/** Tekil güvenlik bulgusu. */
export interface Finding {
  ruleId: string;
  title: string;
  owasp: OwaspCategory;
  severity: Severity;
  /** Açıklama — neden risk. */
  description: string;
  /** Kanıtlar — dosya:satır ya da HTTP trafiği. */
  evidence: Evidence[];
  /** Düzeltme önerisi. */
  remediation: string;
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
