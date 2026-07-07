import { describe, it, expect } from "vitest";
import type { LiveContext, ProbeResult, Project } from "../src/core/rule.js";
import { liveSecurityHeaders } from "../src/live/security-headers.js";
import { liveTransportSecurity } from "../src/live/transport-security.js";
import { liveExposedFiles } from "../src/live/exposed-files.js";
import { liveOpenEndpoints } from "../src/live/open-endpoints.js";
import { liveExposedSecrets } from "../src/live/exposed-secrets.js";
import { evaluateSslDomain } from "../src/live/ssl-domain.js";

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

describe("A05 live — exposed secrets (extended)", () => {
  it(".env.local imzalı 200 → critical/kesin", async () => {
    const f = await liveExposedSecrets.run(
      ctx(
        mkProbe({
          "/.env.local": { status: 200, bodySnippet: "SUPABASE_SERVICE_ROLE_KEY=abc\nDATABASE_URL=postgres://x" },
        }),
      ),
    );
    const env = f.find((x) => x.title.includes(".env.local"));
    expect(env).toBeTruthy();
    expect(env!.severity).toBe("critical");
    expect(env!.confidence).toBe("kesin");
  });

  it("SPA fallback (HTML, imza yok) → bulgu YOK", async () => {
    const f = await liveExposedSecrets.run(
      ctx(
        mkProbe({
          "/.env.local": { status: 200, bodySnippet: "<!doctype html><html><body>app</body></html>" },
          "/config.json": { status: 200, bodySnippet: "<!doctype html>..." },
          "/": { status: 200, bodySnippet: "<html><body>no scripts</body></html>" },
        }),
      ),
    );
    expect(f.length).toBe(0);
  });

  it("config.json sır içeriyorsa → high/kesin", async () => {
    const f = await liveExposedSecrets.run(
      ctx(
        mkProbe({
          "/config.json": { status: 200, bodySnippet: `{"apiUrl":"/api","stripeSecretKey":"sk_***MASKED***"}` },
        }),
      ),
    );
    const c = f.find((x) => x.title.includes("config.json"));
    expect(c).toBeTruthy();
    expect(c!.severity).toBe("high");
  });

  it("config.json sırsız (iyi huylu public config) → bulgu YOK", async () => {
    const f = await liveExposedSecrets.run(
      ctx(
        mkProbe({
          "/config.json": { status: 200, bodySnippet: `{"apiUrl":"/api","theme":"dark","locale":"tr"}` },
        }),
      ),
    );
    expect(f.length).toBe(0);
  });

  it("açıkta source map (.js.map) → medium/kesin", async () => {
    const f = await liveExposedSecrets.run(
      ctx(
        mkProbe({
          "/": { status: 200, bodySnippet: `<html><head><script src="/assets/app-abc123.js"></script></head></html>` },
          "/assets/app-abc123.js.map": {
            status: 200,
            bodySnippet: `{"version":3,"file":"app.js","sources":["../src/index.ts"],"mappings":"AAAA"}`,
          },
        }),
      ),
    );
    const sm = f.find((x) => x.title.includes("kaynak haritası"));
    expect(sm).toBeTruthy();
    expect(sm!.severity).toBe("medium");
  });

  it("source map 404 → bulgu YOK", async () => {
    const f = await liveExposedSecrets.run(
      ctx(
        mkProbe({
          "/": { status: 200, bodySnippet: `<html><head><script src="/assets/app.js"></script></head></html>` },
          // /assets/app.js.map default 404
        }),
      ),
    );
    expect(f.length).toBe(0);
  });
});

describe("A05 live — SSL / domain health", () => {
  const httpsProject: Project = { ...project, url: "https://example.com" };
  function sslCtx(probe: LiveContext["probe"]): LiveContext {
    return { project: httpsProject, baseUrl: "https://example.com", probe };
  }
  const okDns = async () => ({ address: "1.2.3.4" });

  it("BAD: sertifika süresi dolmuş → critical/kesin", async () => {
    const f = await evaluateSslDomain(sslCtx(mkProbe({})), {
      dnsLookup: okDns,
      fetchCert: async () => ({ validTo: "Jan 1 00:00:00 2020 GMT" }),
    });
    const cert = f.find((x) => x.title.includes("DOLMUŞ"));
    expect(cert).toBeTruthy();
    expect(cert!.severity).toBe("critical");
    expect(cert!.confidence).toBe("kesin");
  });

  it("BAD: sertifika <30 gün içinde bitiyor → high/kesin", async () => {
    const soon = new Date(Date.now() + 15 * 86_400_000).toUTCString();
    const f = await evaluateSslDomain(sslCtx(mkProbe({})), {
      dnsLookup: okDns,
      fetchCert: async () => ({ validTo: soon }),
    });
    const cert = f.find((x) => x.title.includes("gün içinde bitiyor"));
    expect(cert).toBeTruthy();
    expect(cert!.severity).toBe("high");
  });

  it("CLEAN: geçerli cert (uzun süre) + HTTP→HTTPS 301 → bulgu YOK", async () => {
    const far = new Date(Date.now() + 200 * 86_400_000).toUTCString();
    const f = await evaluateSslDomain(
      sslCtx(
        mkProbe({
          "http://example.com/": { status: 301, headers: { location: "https://example.com/" } },
        }),
      ),
      { dnsLookup: okDns, fetchCert: async () => ({ validTo: far }) },
    );
    expect(f.length).toBe(0);
  });

  it("BAD: DNS çözülemedi → medium bulgu, erken dön", async () => {
    const f = await evaluateSslDomain(sslCtx(mkProbe({})), {
      dnsLookup: async () => {
        throw new Error("ENOTFOUND");
      },
      fetchCert: async () => ({ validTo: "Jan 1 00:00:00 2020 GMT" }),
    });
    expect(f.length).toBe(1);
    expect(f[0].title).toContain("DNS çözülemedi");
    expect(f[0].severity).toBe("medium");
  });

  it("BAD: HTTP düz 200 (HTTPS'e yönlendirmiyor) → medium", async () => {
    const far = new Date(Date.now() + 200 * 86_400_000).toUTCString();
    const f = await evaluateSslDomain(
      sslCtx(
        mkProbe({
          "http://example.com/": { status: 200, bodySnippet: "<html>plain http</html>" },
        }),
      ),
      { dnsLookup: okDns, fetchCert: async () => ({ validTo: far }) },
    );
    expect(f.some((x) => x.title.includes("yönlendirmiyor"))).toBe(true);
  });
});
