import type { Evidence } from "../core/finding.js";
import type { StaticContext } from "../core/rule.js";

/**
 * "Nocturn Standartları" profili — OWASP kurallarından ayrı, Yiğit'in yazılı
 * güvenlik + hız standartlarını (feedback_security / feedback_hiz_standardi)
 * somut statik kontrollere çeviren kural seti.
 *
 * OWASP bulgularından farkı: her kontrol HER ZAMAN bir sonuç üretir
 * (geçti / kaldı / manuel doğrula / uygulanamaz) — böylece rapor bir
 * "checklist" gibi okunur, yalnızca hata listesi gibi değil.
 */

export type StandardsCategory = "guvenlik" | "hiz";

/** Kontrol seviyesi. Kesin olmayan sezgisel kontroller kritik GÖSTERİLMEZ. */
export type StandardsLevel = "kritik" | "uyari" | "bilgi";

/**
 * Kontrol sonucu:
 *  - "gecti"       → standart karşılanıyor.
 *  - "kaldi"       → standart karşılanmıyor (kanıtlı / yüksek güven).
 *  - "manuel"      → sezgisel sinyal var ama kesin değil — elle doğrulanmalı.
 *  - "uygulanamaz" → bu projede anlamlı değil (ör. Supabase yoksa RLS).
 */
export type StandardsStatus = "gecti" | "kaldi" | "manuel" | "uygulanamaz";

/** Bir kontrolün run() çıktısı — meta alanlar runner tarafından eklenir. */
export interface StandardsCheckOutcome {
  status: StandardsStatus;
  /** İnsan-okunur açıklama: neden geçti / neden kaldı / ne doğrulanmalı. */
  detail: string;
  evidence?: Evidence[];
  /** Bulguya göre seviye override (varsayılan: kontrolün kendi seviyesi). */
  level?: StandardsLevel;
}

export interface StandardsCheck {
  id: string;
  title: string;
  category: StandardsCategory;
  level: StandardsLevel;
  /** Kontrolün neyi aradığı (standart maddesi). */
  description: string;
  /** Kaldıysa nasıl düzeltilir. */
  remediation: string;
  run(ctx: StaticContext): StandardsCheckOutcome | Promise<StandardsCheckOutcome>;
}

/** Rapora yazılan tekil kontrol sonucu. */
export interface StandardsCheckResult {
  id: string;
  title: string;
  category: StandardsCategory;
  level: StandardsLevel;
  status: StandardsStatus;
  detail: string;
  remediation: string;
  evidence: Evidence[];
}

export interface StandardsStatusCounts {
  gecti: number;
  kaldi: number;
  manuel: number;
  uygulanamaz: number;
}

export interface StandardsCategorySummary extends StandardsStatusCounts {
  /** 0-100 sağlık puanı (yüksek = iyi). */
  score: number;
}

/** JSON rapora eklenen profil bloğu (geriye-uyumlu, opsiyonel alan). */
export interface StandardsResult {
  profile: "nocturn-standards";
  version: 1;
  /** 0-100 genel sağlık puanı (yüksek = iyi). */
  score: number;
  counts: StandardsStatusCounts;
  categories: Record<StandardsCategory, StandardsCategorySummary>;
  checks: StandardsCheckResult[];
}
