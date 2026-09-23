import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverStack, expandPath, loadRegistry } from "../src/registry.js";

describe("expandPath", () => {
  it("expands the tilde to home", () => {
    const p = expandPath("~/Desktop/x");
    expect(p).not.toContain("~");
    expect(p).toContain("Desktop");
  });
});

describe("discoverStack", () => {
  it("detects next + supabase + clerk from package.json", () => {
    const dir = mkdtempSync(join(tmpdir(), "nocturn-"));
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({
        dependencies: {
          next: "15.0.0",
          "@supabase/supabase-js": "2.0.0",
          "@clerk/nextjs": "5.0.0",
        },
      }),
    );
    const stack = discoverStack(dir);
    expect(stack.framework).toBe("next");
    expect(stack.db).toBe("supabase");
    expect(stack.auth).toBe("clerk");
  });

  it("detects vite + neon + next-auth", () => {
    const dir = mkdtempSync(join(tmpdir(), "nocturn-"));
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({
        devDependencies: { vite: "5.0.0" },
        dependencies: {
          "@neondatabase/serverless": "0.9.0",
          "next-auth": "4.0.0",
        },
      }),
    );
    const stack = discoverStack(dir);
    expect(stack.framework).toBe("vite");
    expect(stack.db).toBe("neon");
    expect(stack.auth).toBe("next-auth");
  });

  it("does not override the fields that were given", () => {
    const dir = mkdtempSync(join(tmpdir(), "nocturn-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { next: "15" } }));
    const stack = discoverStack(dir, { framework: "vite" });
    expect(stack.framework).toBe("vite");
  });
});

describe("loadRegistry", () => {
  it("reads targets.json, defaults owned to false, discovers the stack", () => {
    const dir = mkdtempSync(join(tmpdir(), "nocturn-"));
    const proj = join(dir, "proj");
    mkdirSync(proj);
    writeFileSync(
      join(proj, "package.json"),
      JSON.stringify({ dependencies: { next: "15", "@clerk/nextjs": "5" } }),
    );
    const t = join(dir, "targets.json");
    writeFileSync(
      t,
      JSON.stringify({ projects: [{ name: "proj", path: proj }] }),
    );
    const projects = loadRegistry(t);
    expect(projects.length).toBe(1);
    expect(projects[0].owned).toBe(false);
    expect(projects[0].stack.framework).toBe("next");
    expect(projects[0].stack.auth).toBe("clerk");
  });

  it("an empty list when the file does not exist", () => {
    expect(loadRegistry("/nonexistent/targets.json")).toEqual([]);
  });
});
