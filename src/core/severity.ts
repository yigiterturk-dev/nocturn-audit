/**
 * Severity seviyeleri ve CVSS-benzeri skorlama.
 * Sadece tespit + raporlama için — exploit yok.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Her severity için ağırlık (toplam risk skoru hesabında kullanılır). */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 6,
  medium: 3,
  low: 1,
  info: 0,
};

/** Terminalde sıralama için (küçük = daha kritik). */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/** Bulgu sayımlarından toplam ağırlıklı risk skoru. */
export function riskScore(counts: SeverityCounts): number {
  return (
    counts.critical * SEVERITY_WEIGHT.critical +
    counts.high * SEVERITY_WEIGHT.high +
    counts.medium * SEVERITY_WEIGHT.medium +
    counts.low * SEVERITY_WEIGHT.low +
    counts.info * SEVERITY_WEIGHT.info
  );
}
