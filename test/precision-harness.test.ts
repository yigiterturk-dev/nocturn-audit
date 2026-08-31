import { describe, it, expect } from "vitest";
import {
  fingerprint, computePrecision, syncLabels, type Labels,
} from "../src/precision.js";
import type { Finding } from "../src/core/finding.js";

// a different snippet -> a different fingerprint (content-based identity).
function f(ruleId: string, file: string, line: number, snip = "kod"): Finding {
  return {
    ruleId, title: "t", owasp: "A04:2021-Insecure Design", severity: "low",
    description: "d", remediation: "r",
    evidence: [{ kind: "file", file, line, snippet: snip }],
  };
}

describe("precision — fingerprint", () => {
  it("rule::file::snippet — content based, unaffected by line shifts", () => {
    // The same snippet on a different line -> THE SAME identity
    expect(fingerprint(f("r1", "a.py", 5, "INSERT INTO t")))
      .toBe(fingerprint(f("r1", "a.py", 99, "INSERT INTO t")));
    expect(fingerprint(f("r1", "a.py", 5, "INSERT INTO t")))
      .toBe("r1::a.py::INSERT INTO t");
  });
  it("falls back to the line when there is no snippet (last resort)", () => {
    const g: Finding = { ...f("r1", "a.py", 5), evidence: [{ kind: "file", file: "a.py", line: 5 }] };
    expect(fingerprint(g)).toBe("r1::a.py::L5");
  });
});

describe("precision — computePrecision", () => {
  it("tp/fp/unlabeled are counted correctly, precision per rule", () => {
    const findings = [f("r1", "a.py", 1, "s1"), f("r1", "b.py", 2, "s2"), f("r2", "c.py", 3, "s3")];
    const labels: Labels = {
      "r1::a.py::s1": { verdict: "tp", rule: "r1", file: "a.py", line: 1 },
      "r1::b.py::s2": { verdict: "fp", rule: "r1", file: "b.py", line: 2 },
      // r2 etiketsiz
    };
    const rep = computePrecision(findings, labels);
    const r1 = rep.perRule.find((r) => r.rule === "r1")!;
    expect(r1.tp).toBe(1); expect(r1.fp).toBe(1); expect(r1.precision).toBe(0.5);
    const r2 = rep.perRule.find((r) => r.rule === "r2")!;
    expect(r2.unlabeled).toBe(1); expect(r2.precision).toBeNull();
    expect(rep.overall.precision).toBe(0.5);
  });
});

describe("precision — syncLabels", () => {
  it("yeni bulgu '?' ile eklenir, mevcut karar KORUNUR", () => {
    const findings = [f("r1", "a.py", 1, "s1"), f("r1", "b.py", 2, "s2")];
    const labels: Labels = {
      "r1::a.py::s1": { verdict: "tp", rule: "r1", file: "a.py", line: 1 },
    };
    const out = syncLabels(findings, labels);
    expect(out.eklenen).toBe(1); expect(out.guncel).toBe(1);
    expect(out.labels["r1::a.py::s1"].verdict).toBe("tp");
    expect(out.labels["r1::b.py::s2"].verdict).toBe("?");
  });
  it("a label that no longer fires is marked 'stale' (never deleted)", () => {
    const findings = [f("r1", "a.py", 1, "s1")];
    const labels: Labels = {
      "r1::a.py::s1": { verdict: "tp", rule: "r1", file: "a.py", line: 1 },
      "r9::eski.py::sx": { verdict: "fp", rule: "r9", file: "eski.py", line: 9 },
    };
    const out = syncLabels(findings, labels);
    expect(out.stale).toBe(1);
    expect(out.labels["r9::eski.py::sx"].note).toBe("stale");
    expect(out.labels["r9::eski.py::sx"].verdict).toBe("fp");
  });
});

import { checkRegressions } from "../src/precision.js";

describe("precision — checkRegressions (the CI gate)", () => {
  it("a labelled TP that no longer fires → lost detection (not clean)", () => {
    const findings = [f("r1", "a.py", 1, "s1")]; // b.py:s2 kayboldu
    const labels: Labels = {
      "r1::a.py::s1": { verdict: "tp", rule: "r1", file: "a.py", line: 1 },
      "r1::b.py::s2": { verdict: "tp", rule: "r1", file: "b.py", line: 2 },
    };
    const r = checkRegressions(findings, labels);
    expect(r.temiz).toBe(false);
    expect(r.lostTp.length).toBe(1);
    expect(r.lostTp[0].file).toBe("b.py");
  });
  it("etiketli-FP geri geldiyse → FP gerilemesi", () => {
    const findings = [f("r1", "a.py", 1, "s1")]; // the fp fired again
    const labels: Labels = {
      "r1::a.py::s1": { verdict: "fp", rule: "r1", file: "a.py", line: 1, note: "stale" },
    };
    const r = checkRegressions(findings, labels);
    expect(r.temiz).toBe(false);
    expect(r.returnedFp.length).toBe(1);
  });
  it("every TP fires and no FP came back → clean", () => {
    const findings = [f("r1", "a.py", 1, "s1")];
    const labels: Labels = {
      "r1::a.py::s1": { verdict: "tp", rule: "r1", file: "a.py", line: 1 },
      "r1::b.py::s2": { verdict: "fp", rule: "r1", file: "b.py", line: 2 }, // retired, not firing
    };
    const r = checkRegressions(findings, labels);
    expect(r.temiz).toBe(true);
  });
});

describe("precision — a resolved TP (the CI gate)", () => {
  it("a tp marked resolved that no longer fires → no problem (a fix)", () => {
    const findings: Finding[] = []; // no longer fires (it was fixed)
    const labels: Labels = {
      "r1::a.py::s1": { verdict: "tp", rule: "r1", file: "a.py", line: 1, note: "resolved 2026-08-24" },
    };
    expect(checkRegressions(findings, labels).temiz).toBe(true);
  });
  it("a tp marked resolved that CAME BACK → a regression (the hole returned)", () => {
    const findings = [f("r1", "a.py", 1, "s1")]; // the fixed hole fired again
    const labels: Labels = {
      "r1::a.py::s1": { verdict: "tp", rule: "r1", file: "a.py", line: 1, note: "resolved 2026-08-24" },
    };
    const r = checkRegressions(findings, labels);
    expect(r.temiz).toBe(false);
    expect(r.lostTp.length).toBe(1);
  });
});
