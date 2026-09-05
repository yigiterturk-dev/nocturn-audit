import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { silentBudgetDenial } from "../src/integrity/silent-budget-denial.js";

/**
 * Real case (gelecekfinans.com, 2026-09-02): a model was asked "are these two
 * reports the same event?" before an article could be written. The helper began
 * with `if (judgeBudget <= 0) return false;` and the cap was 8 calls per run —
 * so after the eighth question every remaining topic was rejected WITHOUT the
 * model being asked. 83 of 112 questions never reached it. Because a budget skip
 * and a genuine rejection were logged identically, the bottleneck was
 * misdiagnosed for weeks as "the judge is too strict".
 */

const run = (files: Record<string, string>) =>
  silentBudgetDenial.run(makeCtx(files)) as Array<{ severity: string; description: string }>;

describe("int — an exhausted paid-call budget answers 'no' by itself", () => {
  it("BAD: the budget guard returns false without asking the model or recording the skip", () => {
    const f = run({
      "lib/bot/writer.ts": `let judgeBudget = 8;
export async function judgeSameStory(a: Brief, b: Brief): Promise<boolean> {
  if (judgeBudget <= 0) return false;
  judgeBudget -= 1;
  const response = await openai().responses.parse({ model: "gpt-4o-mini", input: [] });
  return response.output_parsed?.sameEvent === true;
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
    expect(f[0].description).toContain("judgeBudget");
  });

  it("CLEAN: the skip is counted, so exhaustion stays distinguishable from a decision", () => {
    const f = run({
      "lib/bot/writer.ts": `let judgeBudget = 60;
let judgeSkipped = 0;
export async function judgeSameStory(a: Brief, b: Brief): Promise<boolean> {
  if (judgeBudget <= 0) {
    judgeSkipped += 1;
    return false;
  }
  judgeBudget -= 1;
  const response = await openai().responses.parse({ model: "gpt-4o-mini", input: [] });
  return response.output_parsed?.sameEvent === true;
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a budget guarding a FREE path is not this bug", () => {
    const f = run({
      "lib/cache.ts": `let retryBudget = 3;
export function nextCachedPage(): string | null {
  if (retryBudget <= 0) return null;
  retryBudget -= 1;
  return readFromDisk();
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: throwing is visible — the run stops instead of quietly rejecting", () => {
    const f = run({
      "lib/bot/writer.ts": `let judgeBudget = 60;
export async function judgeSameStory(a: Brief, b: Brief): Promise<boolean> {
  if (judgeBudget <= 0) throw new BudgetExhaustedError("hakem tavanı doldu");
  judgeBudget -= 1;
  const response = await openai().responses.parse({ model: "gpt-4o-mini", input: [] });
  return response.output_parsed?.sameEvent === true;
}`,
    });
    expect(f.length).toBe(0);
  });
});
