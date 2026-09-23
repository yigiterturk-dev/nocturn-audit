import { describe, it, expect } from "vitest";
import type { LiveContext, ProbeResult, Project } from "../src/core/rule.js";
import { liveCorsMisconfig } from "../src/live/cors-misconfig.js";
import { liveHttpMethods } from "../src/live/http-methods.js";
import { liveDirectoryListing } from "../src/live/directory-listing.js";

const project: Project = {
  name: "t", path: "/t", url: "https://example.com", owned: true, stack: {},
};

function mkProbe(
  responses: Record<string, Partial<ProbeResult> & { status: number; headers?: Record<string, string>; bodySnippet?: string }>,
): LiveContext["probe"] {
  return async (path: string, init?: RequestInit): Promise<ProbeResult> => {
    const key = path.split("?")[0];
    const r = responses[path] ?? responses[key];
    if (!r) {
      return {
        ok: true, url: "https://example.com" + path, method: init?.method ?? "GET",
        status: 404, statusText: "Not Found", headers: {}, bodySnippet: "",
        requestLine: `${init?.method ?? "GET"} https://example.com${path}`, responseLine: "HTTP 404",
      };
    }
    return {
      ok: true, url: "https://example.com" + path, method: init?.method ?? "GET",
      status: r.status, statusText: r.statusText ?? "", headers: r.headers ?? {},
      bodySnippet: r.bodySnippet ?? "",
      requestLine: `${init?.method ?? "GET"} https://example.com${path}`, responseLine: `HTTP ${r.status}`,
    };
  };
}

function ctx(probe: LiveContext["probe"]): LiveContext {
  return { project, baseUrl: "https://example.com", probe };
}

describe("A05 live — CORS misconfig", () => {
  it("BAD: reflects a foreign Origin → high finding", async () => {
    const f = await liveCorsMisconfig.run(ctx(mkProbe({
      "/": { status: 200, headers: { "access-control-allow-origin": "https://evil.example" } },
    })));
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });
  it("BAD: wildcard + credentials → high finding", async () => {
    const f = await liveCorsMisconfig.run(ctx(mkProbe({
      "/": { status: 200, headers: { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" } },
    })));
    expect(f.length).toBe(1);
  });
  it("CLEAN: no ACAO header → no finding", async () => {
    const f = await liveCorsMisconfig.run(ctx(mkProbe({ "/": { status: 200, headers: {} } })));
    expect(f.length).toBe(0);
  });
});

describe("A05 live — HTTP methods", () => {
  it("BAD: TRACE returns 200 → finding", async () => {
    const f = await liveHttpMethods.run(ctx(mkProbe({ "/": { status: 200 } })));
    expect(f.some((x) => x.title.includes("TRACE"))).toBe(true);
  });
  it("CLEAN: TRACE rejected (405) → no finding", async () => {
    const f = await liveHttpMethods.run(ctx(mkProbe({ "/": { status: 405 } })));
    expect(f.some((x) => x.title.includes("TRACE"))).toBe(false);
  });
});

describe("A05 live — directory listing", () => {
  it("BAD: /uploads returns an index → finding", async () => {
    const f = await liveDirectoryListing.run(ctx(mkProbe({
      "/uploads": { status: 200, bodySnippet: "<h1>Index of /uploads</h1><ul><li>secret.pdf</li></ul>" },
    })));
    expect(f.length).toBe(1);
    expect(f[0].title).toContain("/uploads");
  });
  it("CLEAN: /uploads returns a normal page → no finding", async () => {
    const f = await liveDirectoryListing.run(ctx(mkProbe({
      "/uploads": { status: 200, bodySnippet: "<html><body>app</body></html>" },
    })));
    expect(f.length).toBe(0);
  });
});
