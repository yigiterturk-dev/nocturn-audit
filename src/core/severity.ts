/**
 * Severity seviyeleri ve CVSS-benzeri skorlama.
 * Detection and reporting only — no exploitation.
 */

import { userLang, dil, type Lang } from "./lang.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Weight per severity (used to compute the total risk score). */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 6,
  medium: 3,
  low: 1,
  info: 0,
};

/** For ordering in the terminal (lower = more critical). */
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

/** The total weighted risk score from the finding counts. */
export function riskScore(counts: SeverityCounts): number {
  return (
    counts.critical * SEVERITY_WEIGHT.critical +
    counts.high * SEVERITY_WEIGHT.high +
    counts.medium * SEVERITY_WEIGHT.medium +
    counts.low * SEVERITY_WEIGHT.low +
    counts.info * SEVERITY_WEIGHT.info
  );
}


/**
 * PİSLİK SKORU — 0-100 arası, projeler arası KARŞILAŞTIRILABİLİR kirlilik.
 *
 * Ham riskScore (ağırlıklı toplam) sınırsızdır: 40 dosyalık projede 2 kritik,
 * 200 dosyalıkta 10 kritik demektir ve ikisini doğru karşılaştırmaz. Pislik
 * skoru ham toplamı sabit bir ölçeğe oturtur:
 *
 *   pislik = min(100, raw × 2)
 *
 * Yani 5 kritik eşdeğeri (5×10) = 100 = "biyolojik tehlike". Lineer ve tek
 * kural: herkes için aynı, açıklaması tek cümle, monoton.
 *
 * DÜRÜSTLÜK ŞARTI (ölçüm kontratıyla aynı mantık): ölçülemeyen kural varsa bu
 * skor bir ALT SINIRDIR — "tertemiz" etiketi yalnız TAM ölçümde geçerlidir.
 * Kısmi ölçümde rapor "(kısmi ölçüm)" ile işaretlenir; 0 bile "temiz" değil
 * "ölçülen kısım temiz" demektir.
 */
export const PISLIK_CARPAN = 2;

export interface Pislik {
  /** 0-100, min(100, raw×2). */
  score: number;
  /** Ham ağırlıklı toplam (geriye-izlenebilirlik için). */
  raw: number;
  /** Ölçüm tam mı? gaps varsa skor alt sınırdır. */
  partial: boolean;
  /** Etiket — terminal/raporda görünen ad. */
  label: string;
}

// Etiketler iki dilli: Türkçe orijinal (beyaz liste sırası korunur),
// İngilizce halka açık sürüm için. Dil NOCTURN_LANG=tr|en (varsayılan en).
const PISLIK_ETIKETLERI: Array<[number, { tr: string; en: string }]> = [
  [0, { tr: "tertemiz", en: "spotless" }],
  [1, { tr: "tozlu", en: "dusty" }],
  [10, { tr: "kirli", en: "dirty" }],
  [30, { tr: "pis", en: "filthy" }],
  [60, { tr: "çok pis", en: "very dirty" }],
  [100, { tr: "biyolojik tehlike", en: "biohazard" }],
];

export function pislikEtiketi(score: number, lang: Lang = userLang()): string {
  let label = dil(lang, PISLIK_ETIKETLERI[0][1].tr, PISLIK_ETIKETLERI[0][1].en);
  for (const [esik, ad] of PISLIK_ETIKETLERI) {
    if (score >= esik) label = dil(lang, ad.tr, ad.en);
  }
  return label;
}

export function pislikSkoru(counts: SeverityCounts, gapsSayisi = 0, lang: Lang = userLang()): Pislik {
  const raw = riskScore(counts);
  const score = Math.min(100, Math.round(raw * PISLIK_CARPAN));
  const partial = gapsSayisi > 0;
  const kismi = dil(lang, " (kısmi ölçüm)", " (partial measurement)");
  return {
    score,
    raw,
    partial,
    label: pislikEtiketi(score, lang) + (partial ? kismi : ""),
  };
}
