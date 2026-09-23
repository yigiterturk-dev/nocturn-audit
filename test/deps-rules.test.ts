import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  outdatedDeps,
  evaluateOutdated,
  findDeprecated,
} from "../src/deps/outdated-deps.js";
import type { DepsContext } from "../src/core/rule.js";

function depsCtx(files: Record<string, string>): { ctx: DepsContext; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "nocturn-deps-"));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content, "utf8");
  }
  const has = new Set(Object.keys(files));
  const ctx: DepsContext = {
    project: { name: "t", path: dir, owned: false, stack: { framework: "next" } },
    root: dir,
    exists: (rel: string) => has.has(rel),
  };
  return { ctx, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("A06 — outdated-deps (deprecated list, offline)", () => {
  it("BAD fixture: deprecated packages (request + node-sass) → low/likely finding", async () => {
    const { ctx, cleanup } = depsCtx({
      "package.json": JSON.stringify({
        name: "x",
        dependencies: { request: "^2.88.0", react: "^18.0.0" },
        devDependencies: { "node-sass": "^7.0.0" },
      }),
      // no node_modules → the npm outdated step is skipped (offline, deterministic)
    });
    try {
      const f = await outdatedDeps.run(ctx);
      expect(f.some((x) => x.title.includes("request"))).toBe(true);
      expect(f.some((x) => x.title.includes("node-sass"))).toBe(true);
      const req = f.find((x) => x.title.includes("request"))!;
      expect(req.severity).toBe("low");
      expect(req.confidence).toBe("likely");
      expect(req.owasp).toContain("A06");
    } finally {
      cleanup();
    }
  });

  it("CLEAN fixture: current, maintained packages → NO finding", async () => {
    const { ctx, cleanup } = depsCtx({
      "package.json": JSON.stringify({
        name: "x",
        dependencies: { react: "^18.0.0", next: "^15.0.0", zod: "^3.23.0" },
      }),
    });
    try {
      const f = await outdatedDeps.run(ctx);
      expect(f.length).toBe(0);
    } finally {
      cleanup();
    }
  });

  it("package.json yoksa → sessiz (bulgu yok)", async () => {
    const { ctx, cleanup } = depsCtx({});
    try {
      const f = await outdatedDeps.run(ctx);
      expect(f.length).toBe(0);
    } finally {
      cleanup();
    }
  });
});

describe("A06 — evaluateOutdated (majors-behind, saf)", () => {
  it(">= 2 majors behind → flagged", () => {
    const out = evaluateOutdated(
      { foo: { current: "2.1.0", wanted: "2.1.0", latest: "5.0.0" } },
      { foo: "^2.1.0" },
    );
    expect(out.length).toBe(1);
    expect(out[0].behind).toBe(3);
  });
  it("1 major behind → noise, not flagged", () => {
    const out = evaluateOutdated(
      { foo: { current: "4.0.0", latest: "5.2.0" } },
      { foo: "^4.0.0" },
    );
    expect(out.length).toBe(0);
  });
  it("with no current, the major is taken from the declared range", () => {
    const out = evaluateOutdated(
      { foo: { latest: "6.0.0" } },
      { foo: "^2.0.0" },
    );
    expect(out.length).toBe(1);
    expect(out[0].curMajor).toBe(2);
  });
  it("a git or invalid latest → skipped (no FP)", () => {
    const out = evaluateOutdated(
      { foo: { current: "1.0.0", latest: "git" } },
      {},
    );
    expect(out.length).toBe(0);
  });
});

describe("A06 — findDeprecated (saf)", () => {
  it("bilinen deprecated bulur", () => {
    expect(findDeprecated({ tslint: "^6.0.0", react: "^18" }).map((d) => d.name)).toEqual([
      "tslint",
    ]);
  });
  it("clean deps → empty", () => {
    expect(findDeprecated({ react: "^18", next: "^15" }).length).toBe(0);
  });
});
