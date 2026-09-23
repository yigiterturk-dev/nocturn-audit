import type { Finding } from "./finding.js";
import { fileEvidence } from "./finding.js";

/**
 * LLM TRIAGE — high/critical bulguların ikinci gözü.
 *
 * İki sağlayıcı, tek arayüz:
 *   1. JEV_AI_API_KEY  → Jev (typesafe.ai systemone). legafetch'teki jev_mevzuat.py
 *      ile aynı sözleşme: {model, state, questions} → {answers: {id: {type, değer}}}.
 *   2. OPENAI_API_KEY  → OpenAI chat (eski yol, geriye-uyumlu).
 *
 * 🔴 EV DOKTRİNİ (legafetch'ten aynen): Jev ARİTMETİK YAPMAZ — ham skor, eşik,
 * kural id'si VERİLMEZ; yalnız bulgu metni + kanıt gider. Jev'in döndürdüğü
 * olasılığı etikete çeviren eşik (0.5) BU DOSYADA, KODDA. Jev patlarsa triyaj
 * sessizce atlanır; tarama asla bozulmaz (null → cli "skipped" der).
 *
 * Triyaj bir YARGI değil bir SORU: "bu kod gerçekten sömürülebilir mi?"
 * Ölçüm (precision korpusu) buradan BAĞIMSIZDIR — etiketler elle/doğrulanmış kalır.
 */

const OPENAI_MODEL = "gpt-4o-mini"; // Swap for a larger model if you want deeper triage.

// Jev sözleşmesi — legafetch-api/jev_mevzuat.py ile AYNI ortam değişkenleri.
// ⚠️ env'ler MODÜL YÜKLENİRKEN değil ÇAĞRI ANINDA okunur: module-load anında
// yakalanan sabit, process.env sonradan değişse bile eski değerde kalır
// (test bu davranışı yakaladı). Triyajı çalıştıracak CI işi key'i kendisi
// export eder; import sırası önemli olmamalı.
const envJevKey = (): string => (process.env.JEV_AI_API_KEY ?? "").trim();
const envJevBase = (): string =>
  (process.env.JEV_AI_BASE_URL ?? "https://api.typesafe.ai").replace(/\/+$/, "");
const envJevModel = (): string => process.env.JEV_AI_MODEL ?? "jev-latest";
const envJevTimeout = (): number => (Number(process.env.JEV_TIMEOUT) || 20) * 1000;
const envOpenaiKey = (): string => (process.env.OPENAI_API_KEY ?? "").trim();

/** Bulgunun gerçek tehdit olma olasılığını etikete çeviren eşik — KODDA, Jev'de değil. */
const TRIAJ_ESIK = 0.5;

export interface LLMAnalysis {
  isRealThreat: boolean;
  explanation: string;
  remediationCode?: string;
}

function jevYapilandirildi(): boolean {
  return Boolean(envJevKey());
}

/**
 * Jev'e GİDEN METİN: bulgunun kendisi + kanıt + dosyanın ilgili bölgesi.
 * Skor, eşik, kural kimliği YOK — yalnız ne görüldüğü.
 */
function bulguMetni(finding: Finding, fileContent: string): string {
  const ev = finding.evidence.find((e) => e.kind === "file");
  const evidenceLines = finding.evidence
    .map((e) => e.snippet || "")
    .filter(Boolean)
    .join("\n")
    .slice(0, 1200);
  // BAĞLAM İŞARETLENEN SATIRA ODAKLI — gerçek vaka (korpus, 2026-09-22): 90.
  // satırdaki fonksiyon auth+rol kontrolüyle açılıyordu ama bağlam dosyanın
  // İLK 3000 karakteriydi; kontrol bağlamda YOKTU ve Jev görmediği korumayı
  // göremeyip 0.81 "kesin açık" dedi. Pencere: işaretlenen satır ± 40.
  const satirNo = ev?.line ?? 0;
  const satirlar = (fileContent ?? "").split(/\r?\n/);
  const bas = Math.max(0, satirNo - 41);
  const son = Math.min(satirlar.length, satirNo + 40);
  const baglam =
    (satirNo > 0
      ? `${bas + 1}-${son} satırları:\n` + satirlar.slice(bas, son).join("\n")
      : (fileContent ?? "").slice(0, 3000)
    ).slice(0, 3000);
  return (
    `Kural: ${finding.ruleId} — ${finding.title} (${finding.owasp})\n` +
    `Açıklama: ${finding.description}\n` +
    `İşaretlenen satır(lar):\n${evidenceLines}\n` +
    `Dosya bağlamı (işaretlenen satırın çevresi):\n${baglam}`
  ).slice(0, 5000);
}

/**
 * Jev systemone çağrısı — legafetch/jev_mevzuat.py ile aynı şekil.
 * state: bulgu metinleri. questions: tipli sorular. Hata → null (asla patlamaz).
 */
async function jevTriyaj(finding: Finding, fileContent: string): Promise<LLMAnalysis | null> {
  const req = fetch(`${envJevBase()}/v1/systemone`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${envJevKey()}`,
    },
    body: JSON.stringify({
      model: envJevModel(),
      state: { bulgu: bulguMetni(finding, fileContent) },
      questions: {
        tehdit: {
          type: "noul",
          instructions:
            "bulgu alanındaki statik analiz bulgusu, verilen bağlamda GERÇEKTEN sömürülebilir " +
            "bir güvenlik açığı mı? Bağlamda özel bir yetki/kimlik kontrolü varsa, uç nokta kasıtlı " +
            "olarak herkese açıksa ya da satır bir test/fixture/placeholder ise olasılık düşer. " +
            "0-1 arası olasılık döndür: 1 = kesin sömürülebilir, 0 = neredeyse kesin yanlış pozitif.",
        },
      },
    }),
    signal: AbortSignal.timeout(envJevTimeout()),
  });

  const yanit = (await req.then((r) => (r.ok ? r.json() : Promise.reject(new Error(`Jev HTTP ${r.status}`))))) as {
    answers?: Record<string, { type?: string; noul?: number }>;
  };

  const a = yanit?.answers?.tehdit;
  if (!a || a.type !== "noul" || typeof a.noul !== "number") return null;

  // ARİTMETİK KODDA: olasılığı etikete çeviren eşik burada.
  const olasilik = Math.min(1, Math.max(0, a.noul));
  const kesin = olasilik >= TRIAJ_ESIK;
  return {
    isRealThreat: kesin,
    explanation:
      `Jev triyajı: gerçek sömürülebilir tehdit olasılığı ${olasilik.toFixed(2)} ` +
      `(eşik ${TRIAJ_ESIK} — eşik koddadır, modele verilmez).`,
  };
}

/** OpenAI yolu — eski davranış, aynen korunur. */
async function openaiTriyaj(finding: Finding, fileContent: string): Promise<LLMAnalysis | null> {
  const evidenceLines = finding.evidence.map((e) => e.snippet || "").join("\n");

  const prompt = `
You are a senior application security engineer reviewing a static-analysis finding.
Our static analysis engine reported a "${finding.title}" (${finding.owasp}) issue in the code below.

Tespit Edilen Kural: ${finding.ruleId}
Description: ${finding.description}

Full file contents (for context):
\`\`\`
${fileContent}
\`\`\`

Flagged lines (analyse only the issue here):
\`\`\`
${evidenceLines}
\`\`\`

Answer the following and return the result as JSON:
1. isRealThreat (boolean): is this genuinely exploitable (true) or a false positive (false)? Important: return false if the file contains a custom auth or credential check, or if the endpoint is deliberately public.
2. explanation (string): briefly explain your reasoning.
3. remediationCode (string): if this is a real issue, give complete working patch code. Otherwise leave it empty.

4. Return VALID JSON ONLY — no markdown fences.
  `.trim();

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${envOpenaiKey()}`,
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      messages: [{ role: "user", content: prompt }],
      temperature: 0.1,
      response_format: { type: "json_object" },
    }),
  });

  if (!response.ok) {
    console.error("OpenAI API error:", await response.text());
    return null;
  }

  const data = (await response.json()) as { choices: Array<{ message: { content: string } }> };
  const result = JSON.parse(data.choices[0].message.content);
  return {
    isRealThreat: result.isRealThreat,
    explanation: result.explanation,
    remediationCode: result.remediationCode,
  };
}

/**
 * Sends a potential hole found by the taint engine to an LLM for confirmation
 * and asks it to write the patch.
 *
 * Sağlayıcı seçimi: JEV_AI_API_KEY varsa Jev (varsayılan), yoksa OpenAI, o da
 * yoksa null (triyaj atlanır, tarama etkilenmez).
 */
export async function analyzeFindingWithLLM(
  finding: Finding,
  fileContent: string,
): Promise<LLMAnalysis | null> {
  try {
    if (jevYapilandirildi()) {
      return await jevTriyaj(finding, fileContent);
    }
    if (envOpenaiKey()) {
      return await openaiTriyaj(finding, fileContent);
    }
    console.warn("JEV_AI_API_KEY / OPENAI_API_KEY yok — LLM triyajı atlandı.");
    return null;
  } catch (error) {
    // Jev patlarsa arama bozulmaz — sadece iyileşme olmaz (legafetch kuralı).
    console.error("LLM triage error:", error);
    return null;
  }
}
