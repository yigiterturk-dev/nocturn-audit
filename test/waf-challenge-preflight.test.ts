import { describe, it, expect } from "vitest";
import { challengeMi } from "../src/core/engine.js";

/**
 * In one run, 28 false "high" findings came from Vercel deployment protection's
 * 403 challenge page. The tool was measuring the challenge, not the application.
 */
describe("live — bot/WAF challenge tespiti", () => {
  it("BAD: a Vercel challenge header → the obstacle is reported", () => {
    expect(
      challengeMi(403, { "x-vercel-mitigated": "challenge" }, "<html>…</html>"),
    ).toMatch(/Vercel/);
  });

  it("BAD: the challenge-token header alone is enough", () => {
    expect(challengeMi(200, { "x-vercel-challenge-token": "2.17876…" }, "")).toMatch(/Vercel/);
  });

  it("BAD: 403 plus a 'Vercel Security Checkpoint' body (no header)", () => {
    expect(
      challengeMi(403, { server: "Vercel" }, "<title>Vercel Security Checkpoint</title>"),
    ).toMatch(/Checkpoint/);
  });

  it("BAD: Cloudflare 'Just a moment' challenge", () => {
    expect(challengeMi(503, {}, "<title>Just a moment...</title>")).toMatch(/Cloudflare/);
  });

  it("GOOD: the application's own 403 (unauthorised) does not count as a challenge", () => {
    expect(challengeMi(403, { "content-type": "application/json" }, '{"error":"forbidden"}')).toBe(
      null,
    );
  });

  it("GOOD: an ordinary 200 page does not count as a challenge", () => {
    expect(challengeMi(200, { server: "Vercel" }, "<html><body>Ana sayfa</body></html>")).toBe(null);
  });
});
