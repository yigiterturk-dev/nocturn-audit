import { describe, it, expect } from "vitest";
import {
  shannonEntropy,
  maxRun,
  classify,
  keyspaceBits,
  bytesKeyspaceBits,
  profile,
  strengthFromBits,
  normalizedEntropy,
  dgaLikeness,
} from "../src/core/shannon.js";

describe("shannonEntropy", () => {
  it("is 0 for empty and single-symbol strings", () => {
    expect(shannonEntropy("")).toBe(0);
    expect(shannonEntropy("aaaaaaaaaaaaaaaa")).toBe(0);
  });

  it("is 1 bit/char for two equiprobable symbols", () => {
    expect(shannonEntropy("ab")).toBeCloseTo(1, 10);
    expect(shannonEntropy("abababab")).toBeCloseTo(1, 10);
  });

  it("reaches 2 bits/char for four distinct symbols", () => {
    expect(shannonEntropy("abcd")).toBeCloseTo(2, 10);
  });
});

describe("maxRun", () => {
  it("sees length without information", () => {
    expect(maxRun("aaaaaaaaaa")).toBe(10);
    expect(maxRun("abcabcabc")).toBe(1);
    expect(maxRun("token12345")).toBe(1); // no adjacent repeats
  });
});

describe("classify", () => {
  it("recognises the encodings that matter", () => {
    expect(classify("deadbeef00")).toBe("hex");
    expect(classify("JBSWY3DPEHPK3PXP")).toBe("base32");
    expect(classify("aGVsbG8gd29ybGQ=")).toBe("base64");
    expect(classify("Ab3xKp9QzT1m")).toBe("alnum");
    expect(classify("sk_live_abc-DEF_123")).toBe("printable");
    expect(classify("merhaba dünya")).toBe("text");
  });
});

describe("keyspaceBits", () => {
  it("measures against the INFERRED alphabet, not the observed one", () => {
    // hex ceiling is 4 bits/char → 8 chars = 32 bits, even with 5 distinct letters
    expect(keyspaceBits("deadbeef")).toBeCloseTo(32, 6);
    // base64 ceiling is 6 bits/char
    expect(keyspaceBits("aGVsbG8gd29ybGQ=")).toBeCloseTo(16 * 6, 10);
  });

  it("handles the alnum class", () => {
    const bits = keyspaceBits("Ab3xKp9QzT1m"); // 12 chars, alnum (62)
    expect(bits).toBeCloseTo(12 * Math.log2(62), 6);
    expect(Math.round(bits)).toBe(71);
  });

  it("is 0 for empty input", () => {
    expect(keyspaceBits("")).toBe(0);
  });
});

describe("strengthFromBits", () => {
  it("bands at 64 and 112", () => {
    expect(strengthFromBits(0)).toBe("weak");
    expect(strengthFromBits(63.9)).toBe("weak");
    expect(strengthFromBits(64)).toBe("marginal");
    expect(strengthFromBits(111.9)).toBe("marginal");
    expect(strengthFromBits(112)).toBe("strong");
    expect(strengthFromBits(256)).toBe("strong");
  });

  it("exposes what a byte count really buys", () => {
    expect(bytesKeyspaceBits(8)).toBe(64);
    expect(strengthFromBits(bytesKeyspaceBits(8))).toBe("marginal");
    expect(strengthFromBits(bytesKeyspaceBits(32))).toBe("strong");
  });
});

describe("normalizedEntropy", () => {
  it("judges a string against its OWN alphabet, not base64's", () => {
    // 40 hex chars of near-constant value: high raw H for a human, poor for hex
    const nearConstant = "dead".repeat(10);
    expect(normalizedEntropy(nearConstant)).toBeLessThan(0.6);

    // uniform hex reaches the ceiling
    expect(normalizedEntropy("0123456789abcdef")).toBeCloseTo(1, 5);
  });
});

describe("profile", () => {
  it("returns one coherent measurement", () => {
    const p = profile("aGVsbG8gd29ybGQ=");
    expect(p.klass).toBe("base64");
    expect(p.length).toBe(16);
    expect(p.ceiling).toBeCloseTo(6, 10);
    expect(p.keyspaceBits).toBeCloseTo(96, 10);
    expect(p.normalized).toBeGreaterThan(0.5);
  });
});

describe("dgaLikeness", () => {
  it("leaves human hostnames alone", () => {
    expect(dgaLikeness("google.com")).toBeLessThan(0.5);
    expect(dgaLikeness("example.com")).toBeLessThan(0.5);
    expect(dgaLikeness("nocturndev.com")).toBeLessThan(0.5);
  });

  it("flags near-uniform, unpronounceable labels", () => {
    expect(dgaLikeness("kx7wqzvbn9.example.com")).toBeGreaterThanOrEqual(0.65);
  });

  it("ignores infrastructure labels and short names", () => {
    expect(dgaLikeness("www.google.com")).toBe(0);
    expect(dgaLikeness("api.io")).toBe(0);
  });
});
