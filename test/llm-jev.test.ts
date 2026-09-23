import { describe, it, expect, vi, afterEach } from "vitest";
import { analyzeFindingWithLLM, type LLMAnalysis } from "../src/core/llm.js";
import type { Finding } from "../src/core/finding.js";

const bulgu: Finding = {
  ruleId: "a02-hardcoded-secret",
  title: "Secret hardcoded",
  owasp: "A02:2021-Cryptographic Failures",
  severity: "high",
  description: "test",
  evidence: [{ kind: "file", file: "src/x.ts", line: 3, snippet: "const token = 'sk_test_x'" }],
  remediation: "rotate",
};

function stubFetch(json: unknown, ok = true) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok, json: async () => json, text: async () => "" })),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("Jev triyajı (systemone sözleşmesi)", () => {
  it("JEV_AI_API_KEY yoksa ve OPENAI yoksa null döner — tarama etkilenmez", async () => {
    vi.stubEnv("JEV_AI_API_KEY", "");
    vi.stubEnv("OPENAI_API_KEY", "");
    const r = await analyzeFindingWithLLM(bulgu, "const x = 1;");
    expect(r).toBeNull();
  });

  it("yüksek olasılık → gerçek tehdit; eşik KODDADIR", async () => {
    stubFetch({ answers: { tehdit: { type: "noul", noul: 0.9 } } });
    vi.stubEnv("JEV_AI_API_KEY", "test-key");
    const r = (await analyzeFindingWithLLM(bulgu, "code")) as LLMAnalysis;
    expect(r.isRealThreat).toBe(true);
    expect(r.explanation).toContain("0.90");
    // aritmetik modele değil koda: çağrı gövdesinde eşik/kural skoru YOK
    const body = JSON.parse((globalThis.fetch as any).mock.calls[0][1].body);
    expect(body.questions.tehdit.type).toBe("noul");
    expect(body.state.bulgu).toContain("a02-hardcoded-secret");
    expect(JSON.stringify(body)).not.toContain("eşik");
  });

  it("düşük olasılık → false positive", async () => {
    stubFetch({ answers: { tehdit: { type: "noul", noul: 0.2 } } });
    vi.stubEnv("JEV_AI_API_KEY", "test-key");
    const r = (await analyzeFindingWithLLM(bulgu, "code")) as LLMAnalysis;
    expect(r.isRealThreat).toBe(false);
  });

  it("eşik tam 0.5'te kesin sayılır (aritmetik KODDA)", async () => {
    stubFetch({ answers: { tehdit: { type: "noul", noul: 0.5 } } });
    vi.stubEnv("JEV_AI_API_KEY", "test-key");
    const r = (await analyzeFindingWithLLM(bulgu, "code")) as LLMAnalysis;
    expect(r.isRealThreat).toBe(true);
  });

  it("HTTP hatası → null, exception fırlatmaz", async () => {
    stubFetch({ err: "nope" }, false);
    vi.stubEnv("JEV_AI_API_KEY", "test-key");
    const r = await analyzeFindingWithLLM(bulgu, "code");
    expect(r).toBeNull();
  });

  it("bozuk/yanlış tipli cevap → null", async () => {
    stubFetch({ answers: { tehdit: { type: "metin", metin: "anlamadım" } } });
    vi.stubEnv("JEV_AI_API_KEY", "test-key");
    expect(await analyzeFindingWithLLM(bulgu, "code")).toBeNull();
  });

  it("OpenAI fallback çalışır (Jev yokken)", async () => {
    stubFetch({ choices: [{ message: { content: JSON.stringify({ isRealThreat: true, explanation: "ok" }) } }] });
    vi.stubEnv("OPENAI_API_KEY", "sk-x");
    const r = (await analyzeFindingWithLLM(bulgu, "code")) as LLMAnalysis;
    expect(r.isRealThreat).toBe(true);
    expect(String((globalThis.fetch as any).mock.calls[0][0])).toContain("openai");
  });
});
