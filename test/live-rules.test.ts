import { describe, it, expect } from "vitest";
import type { LiveContext, ProbeResult, Project } from "../src/core/rule.js";
import { liveSecurityHeaders } from "../src/live/security-headers.js";
import { liveTransportSecurity } from "../src/live/transport-security.js";
import { liveExposedFiles } from "../src/live/exposed-files.js";
import { liveOpenEndpoints } from "../src/live/open-endpoints.js";
import { liveExposedSecrets } from "../src/live/exposed-secrets.js";
import { evaluateSslDomain } from "../src/live/ssl-domain.js";
import { liveUserEnumeration } from "../src/live/user-enumeration.js";

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
  it("produces a finding when the headers are absent", async () => {
    const f = await liveSecurityHeaders.run(
      ctx(mkProbe({ "/": { status: 200, headers: {} } })),
    );
    expect(f.length).toBeGreaterThanOrEqual(3);
  });
  it("no finding when every header is present", async () => {
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
    expect(f.some((x) => x.title.includes("cookie flag"))).toBe(true);
  });
  it("HSTS plus a secure cookie → clean", async () => {
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
  it("a signed .env returning 200 → critical finding", async () => {
    const f = await liveExposedFiles.run(
      ctx(
        mkProbe({
          "/.env": { status: 200, bodySnippet: "DATABASE_URL=postgres://x\nSTRIPE_KEY=sk_test_x" },
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
  it("/admin returning 200 with content and no auth → finding", async () => {
    const f = await liveOpenEndpoints.run(
      ctx(
        mkProbe({
          "/admin": { status: 200, bodySnippet: "<h1>Admin Dashboard</h1><table>users</table>" },
        }),
      ),
    );
    expect(f.length).toBe(1);
  });
  it("/admin redirects to login → no finding", async () => {
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
  it("a signed .env.local returning 200 → critical/certain", async () => {
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
    expect(env!.confidence).toBe("certain");
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

  it("a config.json containing secrets → high/certain", async () => {
    const f = await liveExposedSecrets.run(
      ctx(
        mkProbe({
          "/config.json": { status: 200, bodySnippet: `{"apiUrl":"/api","stripeSecretKey":"sk_test_abcdef123456"}` },
        }),
      ),
    );
    const c = f.find((x) => x.title.includes("config.json"));
    expect(c).toBeTruthy();
    expect(c!.severity).toBe("high");
  });

  it("a config.json with no secrets (a benign public config) → NO finding", async () => {
    const f = await liveExposedSecrets.run(
      ctx(
        mkProbe({
          "/config.json": { status: 200, bodySnippet: `{"apiUrl":"/api","theme":"dark","locale":"tr"}` },
        }),
      ),
    );
    expect(f.length).toBe(0);
  });

  it("an exposed source map (.js.map) → medium/certain", async () => {
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
    const sm = f.find((x) => x.title.includes("source map"));
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

  it("BAD: the certificate has expired → critical/certain", async () => {
    const f = await evaluateSslDomain(sslCtx(mkProbe({})), {
      dnsLookup: okDns,
      fetchCert: async () => ({ validTo: "Jan 1 00:00:00 2020 GMT" }),
    });
    const cert = f.find((x) => x.title.includes("EXPIRED"));
    expect(cert).toBeTruthy();
    expect(cert!.severity).toBe("critical");
    expect(cert!.confidence).toBe("certain");
  });

  it("BAD: the certificate expires within 30 days → high/certain", async () => {
    const soon = new Date(Date.now() + 15 * 86_400_000).toUTCString();
    const f = await evaluateSslDomain(sslCtx(mkProbe({})), {
      dnsLookup: okDns,
      fetchCert: async () => ({ validTo: soon }),
    });
    const cert = f.find((x) => x.title.includes("expires in"));
    expect(cert).toBeTruthy();
    expect(cert!.severity).toBe("high");
  });

  it("CLEAN: a valid cert (long-lived) plus an HTTP→HTTPS 301 → NO finding", async () => {
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

  it("BAD: DNS did not resolve → medium finding, return early", async () => {
    const f = await evaluateSslDomain(sslCtx(mkProbe({})), {
      dnsLookup: async () => {
        throw new Error("ENOTFOUND");
      },
      fetchCert: async () => ({ validTo: "Jan 1 00:00:00 2020 GMT" }),
    });
    expect(f.length).toBe(1);
    expect(f[0].title).toContain("DNS did not resolve");
    expect(f[0].severity).toBe("medium");
  });

  it("BAD: plain HTTP 200 (no redirect to HTTPS) → medium", async () => {
    const far = new Date(Date.now() + 200 * 86_400_000).toUTCString();
    const f = await evaluateSslDomain(
      sslCtx(
        mkProbe({
          "http://example.com/": { status: 200, bodySnippet: "<html>plain http</html>" },
        }),
      ),
      { dnsLookup: okDns, fetchCert: async () => ({ validTo: far }) },
    );
    expect(f.some((x) => x.title.includes("does not redirect"))).toBe(true);
  });
});

describe("a01 — open endpoints cannot be scanned on a catch-all server", () => {
  const yanit = (status: number, body = "<html>kabuk</html>") => ({
    ok: status >= 200 && status < 400,
    url: "http://x", method: "GET", status, statusText: "",
    headers: { "content-type": "text/html" }, bodySnippet: body,
    requestLine: "GET /x", responseLine: `200 ${status}`,
  });

  it("INFO: when a nonexistent path also returns 200, it SAYS the measurement failed", async () => {
    // SPAs and Next.js return 200 and the same HTML shell for every unknown path.
    // In that case "/admin returned 200" says nothing — a nonexistent path returns
    // 200 too. Without the distinction every SPA gets four false HIGHs.
    const { liveOpenEndpoints } = await import("../src/live/open-endpoints.js");
    const f = await liveOpenEndpoints.run({
      project: { name: "t", path: "", owned: true, stack: {} },
      baseUrl: "http://x",
      probe: async () => yanit(200),
    } as never) as Array<{ severity: string; title: string }>;

    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].title).toContain("not possible");
  });

  it("FINDING: when a nonexistent path returns 404, open endpoints really are measured", async () => {
    const { liveOpenEndpoints } = await import("../src/live/open-endpoints.js");
    let first = true;
    const f = await liveOpenEndpoints.run({
      project: { name: "t", path: "", owned: true, stack: {} },
      baseUrl: "http://x",
      probe: async () => {
        if (first) { first = false; return yanit(404, "yok"); }
        return yanit(200, '{"users":[{"id":1,"role":"admin"}]}');
      },
    } as never) as Array<{ severity: string }>;

    expect(f.length).toBeGreaterThan(0);
    expect(f.every((x) => x.severity === "high")).toBe(true);
  });
});

/**
 * In one project the login route DID have an 8-per-10-minutes rate limit in code,
 * but the probe said "no signal" — the same-origin gate in front of the brake
 * turned the probe away with a 403. The measurement never got there. "Could not
 * measure" and "not present" are not the same thing.
 */
describe("A07 live — when login throttling cannot be measured", () => {
  it("BAD measurement: an origin/CSRF rejection → not a finding but an INFO 'not measured'", async () => {
    const f = await liveUserEnumeration.run(
      ctx(
        mkProbe({
          "/api/auth/login": {
            status: 403,
            bodySnippet: '{"error":"Geçersiz istek kaynağı."}',
          },
        }),
      ),
    );
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].title).toMatch(/COULD NOT BE MEASURED/);
  });

  it("BAD: when there really is no brake (200, no header) the medium finding stands", async () => {
    const f = await liveUserEnumeration.run(
      ctx(mkProbe({ "/api/auth/login": { status: 401, bodySnippet: '{"error":"E-posta veya parola hatalı."}' } })),
    );
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });

  it("GOOD: no finding when it returns 429", async () => {
    const f = await liveUserEnumeration.run(
      ctx(mkProbe({ "/api/auth/login": { status: 429, headers: { "retry-after": "60" } } })),
    );
    expect(f.length).toBe(0);
  });
});
