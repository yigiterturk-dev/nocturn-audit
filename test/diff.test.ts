import { describe, it, expect } from "vitest";
import { computeDiff } from "../src/diff.js";

/**
 * Three lines were written to add a brake to an SSRF hole, the next run showed
 * no finding, and it looked "fixed". In fact the rule's ±6 line window had
 * shifted — the brake was never recognised and the hole was still there.
 *
 * These tests pin down the mechanism that catches that moment: if the finding is
 * gone but the file never changed, what changed is the RULE, not the code.
 */
const rapor = (
  findings: Array<{ rule: string; file: string; snippet: string }>,
  ozetler: Record<string, string>,
) => ({
  projects: [
    {
      project: { name: "Gama" },
      findings: findings.map((b) => ({
        ruleId: b.rule,
        title: "t",
        severity: "high",
        evidence: [{ kind: "file", file: b.file, line: 10, snippet: b.snippet }],
      })),
      fileDigests: ozetler,
    },
  ],
});

describe("diff — was the vanished finding really fixed", () => {
  it("SUSPICIOUS: the finding is gone and the file is IDENTICAL → not a fix", () => {
    const once = rapor([{ rule: "a10-ssrf", file: "runner.ts", snippet: "fetch(target)" }], {
      "runner.ts": "aaaa1111bbbb2222",
    });
    const sonra = rapor([], { "runner.ts": "aaaa1111bbbb2222" });
    const f = computeDiff(once, sonra);
    expect(f.vanished.length).toBe(1);
    expect(f.suspicious.length).toBe(1);
    expect(f.suspicious[0].reason).toBe("file-identical");
  });

  it("CLEAN: the finding is gone and the file CHANGED → possibly a fix", () => {
    const once = rapor([{ rule: "a10-ssrf", file: "runner.ts", snippet: "fetch(target)" }], {
      "runner.ts": "aaaa1111bbbb2222",
    });
    const sonra = rapor([], { "runner.ts": "cccc3333dddd4444" });
    const f = computeDiff(once, sonra);
    expect(f.vanished.length).toBe(1);
    expect(f.suspicious.length).toBe(0);
  });

  it("new findings are listed separately", () => {
    const once = rapor([], {});
    const sonra = rapor([{ rule: "a01-idor", file: "route.ts", snippet: "x" }], {
      "route.ts": "ffff",
    });
    const f = computeDiff(once, sonra);
    expect(f.yeni.length).toBe(1);
    expect(f.vanished.length).toBe(0);
  });

  it("a line shift does not count a finding as 'vanished' (identity comes from content)", () => {
    // The same code on a different line → the same finding.
    const once = {
      projects: [
        {
          project: { name: "p" },
          findings: [
            {
              ruleId: "r",
              title: "t",
              severity: "low",
              evidence: [{ kind: "file", file: "a.ts", line: 10, snippet: "fetch(target)" }],
            },
          ],
          fileDigests: { "a.ts": "1111" },
        },
      ],
    };
    const sonra = {
      projects: [
        {
          project: { name: "p" },
          findings: [
            {
              ruleId: "r",
              title: "t",
              severity: "low",
              evidence: [{ kind: "file", file: "a.ts", line: 42, snippet: "fetch(target)" }],
            },
          ],
          fileDigests: { "a.ts": "2222" },
        },
      ],
    };
    const f = computeDiff(once, sonra);
    expect(f.vanished.length).toBe(0);
    expect(f.yeni.length).toBe(0);
  });
});
