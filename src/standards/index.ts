import type { StaticContext } from "../core/rule.js";
import type {
  StandardsCategory,
  StandardsCategorySummary,
  StandardsCheck,
  StandardsCheckResult,
  StandardsLevel,
  StandardsResult,
  StandardsStatusCounts,
} from "./types.js";
import { securityChecks } from "./security.js";
import { performanceChecks } from "./performance.js";

export type {
  StandardsCategory,
  StandardsCheck,
  StandardsCheckResult,
  StandardsLevel,
  StandardsResult,
  StandardsStatus,
} from "./types.js";

/** Aktif "Nocturn Standartları" kontrol seti (güvenlik + hız). */
export const standardsChecks: StandardsCheck[] = [
  ...securityChecks,
  ...performanceChecks,
];

/**
 * "Kaldı" durumundaki kontrolün seviye bazlı puan cezası.
 * "manuel" ceza almaz (yanlış-pozitif skoru düşürmesin — sadece görünür kalsın).
 */
const FAIL_PENALTY: Record<StandardsLevel, number> = {
  kritik: 25,
  uyari: 10,
  bilgi: 3,
};

function emptyStatusCounts(): StandardsStatusCounts {
  return { gecti: 0, kaldi: 0, manuel: 0, uygulanamaz: 0 };
}

function summarize(results: StandardsCheckResult[]): StandardsCategorySummary {
  const counts = emptyStatusCounts();
  let penalty = 0;
  for (const r of results) {
    counts[r.status]++;
    if (r.status === "kaldi") penalty += FAIL_PENALTY[r.level];
  }
  return { ...counts, score: Math.max(0, Math.min(100, 100 - penalty)) };
}

/**
 * Nocturn Standartları profilini çalıştırır. Her kontrol her zaman bir sonuç
 * üretir; kontrol hata fırlatırsa "manuel" olarak işaretlenir (tarama düşmez).
 */
export async function runStandards(ctx: StaticContext): Promise<StandardsResult> {
  const checks: StandardsCheckResult[] = [];
  for (const check of standardsChecks) {
    try {
      const out = await Promise.resolve(check.run(ctx));
      checks.push({
        id: check.id,
        title: check.title,
        category: check.category,
        level: out.level ?? check.level,
        status: out.status,
        detail: out.detail,
        remediation: check.remediation,
        evidence: out.evidence ?? [],
      });
    } catch (err) {
      checks.push({
        id: check.id,
        title: check.title,
        category: check.category,
        level: check.level,
        status: "manuel",
        detail: `Kontrol çalışırken hata verdi: ${err instanceof Error ? err.message : String(err)} — elle doğrulayın.`,
        remediation: check.remediation,
        evidence: [],
      });
    }
  }

  const byCat = (cat: StandardsCategory) =>
    summarize(checks.filter((c) => c.category === cat));
  const overall = summarize(checks);

  return {
    profile: "nocturn-standards",
    version: 1,
    score: overall.score,
    counts: {
      gecti: overall.gecti,
      kaldi: overall.kaldi,
      manuel: overall.manuel,
      uygulanamaz: overall.uygulanamaz,
    },
    categories: {
      guvenlik: byCat("guvenlik"),
      hiz: byCat("hiz"),
    },
    checks,
  };
}
