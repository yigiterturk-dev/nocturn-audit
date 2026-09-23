import { describe, it, expect } from "vitest";

/**
 * One project was registered as `http://…sslip.io` while Caddy 308'd to https.
 * Because probes run with manual redirects, every live rule measured the 308
 * response and produced five false findings ("no CSP", "no X-Frame-Options",
 * "no rate limit on login"). All of them were present on the https side.
 */
import { redirectTarget } from "../src/core/engine.js";

const result = (status: number, location?: string) => ({
  ok: true,
  url: "http://example.test/",
  method: "GET",
  status,
  statusText: "",
  headers: location ? { location } : {},
  bodySnippet: "",
  requestLine: "",
  responseLine: "",
});

describe("live — the base URL redirect is normalised", () => {
  it("BAD: http→https 308 on the same host → returns the target", () => {
    expect(
      redirectTarget("http://example.test", result(308, "https://example.test/") as never),
    ).toBe("https://example.test");
  });

  it("BAD: 301 de izlenir", () => {
    expect(
      redirectTarget("http://example.test", result(301, "https://example.test/") as never),
    ).toBe("https://example.test");
  });

  it("GOOD: no redirect in a 200 response", () => {
    expect(redirectTarget("https://example.test", result(200) as never)).toBe(null);
  });

  // vega.Lambda.com `/` → `/login` 302'liyordu. Bunu taban saymak, sonraki
  // sends every probe to nonexistent addresses like `/login/api/health`.
  it("GOOD: a PATH redirect within the same origin is not taken as the base", () => {
    expect(
      redirectTarget("https://example.test", result(302, "https://example.test/login") as never),
    ).toBe(null);
  });
  it("BAD: when the origin changes the path is dropped and only the origin is taken", () => {
    expect(
      redirectTarget("http://example.test", result(308, "https://example.test/tr/") as never),
    ).toBe("https://example.test");
  });

  it("GOOD: a redirect to ANOTHER host is not followed (it may not be what we meant to measure)", () => {
    expect(
      redirectTarget("http://example.test", result(308, "https://baska.test/") as never),
    ).toBe(null);
  });

  it("GOOD: null when there is no Location header", () => {
    expect(redirectTarget("http://example.test", result(308) as never)).toBe(null);
  });

  it("GOOD: null when the probe got no answer at all (fail-closed is handled elsewhere)", () => {
    expect(
      redirectTarget("http://example.test", { ...result(308, "https://example.test/"), ok: false } as never),
    ).toBe(null);
  });
});
