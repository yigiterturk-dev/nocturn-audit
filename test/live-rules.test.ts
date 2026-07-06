import { describe, it, expect } from "vitest";
import type { LiveContext, ProbeResult, Project } from "../src/core/rule.js";
import { liveSecurityHeaders } from "../src/live/security-headers.js";
import { liveTransportSecurity } from "../src/live/transport-security.js";
import { liveExposedFiles } from "../src/live/exposed-files.js";
import { liveOpenEndpoints } from "../src/live/open-endpoints.js";

const project: Project = {
  name: "t",
  path: "/t",
  url: "https://example.com",
  owned: true,
  stack: { framework: "next" },
};

function mkProbe(
  responses: Record<
    string,
    Partial<ProbeResult> & { status: number; headers?: Record<string, string>; bodySnippet?: string }
  >,
): LiveContext["probe"] {
  return async (path: string): Promise<ProbeResult> => {
    const key = path.split("?")[0];
    const r = responses[path] ?? responses[key];
    if (!r) {
      return {
        ok: true,
        url: "https://example.com" + path,
        method: "GET",
        status: 404,
        statusText: "Not Found",
        headers: {},
        bodySnippet: "",
        requestLine: `GET https://example.com${path}`,
        responseLine: "HTTP 404",
      };
    }
    return {
      ok: true,
      url: "https://example.com" + path,
      method: "GET",
      status: r.status,
      statusText: r.statusText ?? "",
      headers: r.headers ?? {},
      bodySnippet: r.bodySnippet ?? "",
      requestLine: `GET https://example.com${path}`,
      responseLine: `HTTP ${r.status}`,
    };
  };
}

function ctx(probe: LiveContext["probe"]): LiveContext {
  return { project, baseUrl: "https://example.com", probe };
}

describe("A05 live — security headers", () => {
  it("header yoksa bulgu üretir", async () => {
    const f = await liveSecurityHeaders.run(
      ctx(mkProbe({ "/": { status: 200, headers: {} } })),
    );
    expect(f.length).toBeGreaterThanOrEqual(3);
  });
  it("tüm headerlar varsa bulgu yok", async () => {
    const f = await liveSecurityHeaders.run(
      ctx(
        mkProbe({
          "/": {
            status: 200,
            headers: {
              "content-security-policy": "default-src 'self'",
              "x-frame-options": "DENY",
              "x-content-type-options": "nosniff",
              "referrer-policy": "strict-origin-when-cross-origin",
            },
          },
        }),
      ),
    );
    expect(f.length).toBe(0);
  });
});

describe("A02 live — transport & cookies", () => {
  it("HSTS yok + cookie flag yok → bulgu", async () => {
    const f = await liveTransportSecurity.run(
      ctx(
        mkProbe({
          "/": {
            status: 200,
            headers: { "set-cookie": "session=abc; Path=/" },
          },
        }),
      ),
    );
    expect(f.some((x) => x.title.includes("HSTS"))).toBe(true);
    expect(f.some((x) => x.title.includes("Cookie"))).toBe(true);
  });
  it("HSTS + güvenli cookie → temiz", async () => {
    const f = await liveTransportSecurity.run(
      ctx(
        mkProbe({
          "/": {
            status: 200,
            headers: {
              "strict-transport-security": "max-age=63072000",
              "set-cookie": "session=abc; HttpOnly; Secure; SameSite=Lax",
            },
          },
        }),
      ),
    );
    expect(f.length).toBe(0);
  });
});

describe("A05 live — exposed files", () => {
  it(".env imzalı 200 → critical bulgu", async () => {
    const f = await liveExposedFiles.run(
      ctx(
        mkProbe({
          "/.env": { status: 200, bodySnippet: "DATABASE_URL=postgres://x\nSTRIPE_KEY=sk_live_x" },
        }),
      ),
    );
    expect(f.some((x) => x.severity === "critical")).toBe(true);
  });
  it("SPA fallback (HTML, imza yok) → bulgu yok", async () => {
    const f = await liveExposedFiles.run(
      ctx(
        mkProbe({
          "/.env": { status: 200, bodySnippet: "<!doctype html><html>...</html>" },
        }),
      ),
    );
    expect(f.length).toBe(0);
  });
});

describe("A01 live — open endpoints", () => {
  it("/admin auth'suz 200 içerik → bulgu", async () => {
    const f = await liveOpenEndpoints.run(
      ctx(
        mkProbe({
          "/admin": { status: 200, bodySnippet: "<h1>Admin Dashboard</h1><table>users</table>" },
        }),
      ),
    );
    expect(f.length).toBe(1);
  });
  it("/admin login'e yönlendiriyor → bulgu yok", async () => {
    const f = await liveOpenEndpoints.run(
      ctx(
        mkProbe({
          "/admin": { status: 200, bodySnippet: "Please sign in to continue" },
        }),
      ),
    );
    expect(f.length).toBe(0);
  });
});
