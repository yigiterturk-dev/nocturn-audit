import type { Finding } from "./finding.js";
import { fileEvidence } from "./finding.js";

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MODEL = "gpt-4o-mini"; // Swap for a larger model if you want deeper triage.

export interface LLMAnalysis {
  isRealThreat: boolean;
  explanation: string;
  remediationCode?: string;
}

/**
 * Sends a potential hole found by the taint engine to an LLM for confirmation
 * and asks it to write the patch.
 */
export async function analyzeFindingWithLLM(
  finding: Finding,
  fileContent: string
): Promise<LLMAnalysis | null> {
  if (!OPENAI_API_KEY) {
    console.warn("OPENAI_API_KEY is not set — skipping LLM triage.");
    return null;
  }

  // Give only the relevant lines as context
  const evidenceLines = finding.evidence.map(e => e.snippet || "").join("\n");
  
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

  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.1,
        response_format: { type: "json_object" }
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      console.error("OpenAI API error:", err);
      return null;
    }

    const data = await response.json() as any;
    const result = JSON.parse(data.choices[0].message.content);
    
    return {
      isRealThreat: result.isRealThreat,
      explanation: result.explanation,
      remediationCode: result.remediationCode
    };
  } catch (error) {
    console.error("LLM triage error:", error);
    return null;
  }
}
