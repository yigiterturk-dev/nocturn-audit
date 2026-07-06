import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverStack, expandPath, loadRegistry } from "../src/registry.js";

describe("expandPath", () => {
  it("tilde'yi home ile açar", () => {
    const p = expandPath("~/Desktop/x");
    expect(p).not.toContain("~");
    expect(p).toContain("Desktop");
  });
});

describe("discoverStack", () => {
  it("package.json'dan next + supabase + clerk çıkarır", () => {
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

  it("vite + neon + next-auth çıkarır", () => {
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

  it("verilen alanları override etmez", () => {
    const dir = mkdtempSync(join(tmpdir(), "nocturn-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { next: "15" } }));
    const stack = discoverStack(dir, { framework: "vite" });
    expect(stack.framework).toBe("vite");
  });
});

describe("loadRegistry", () => {
  it("targets.json okur, owned varsayılan false, stack keşfeder", () => {
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

  it("dosya yoksa boş liste", () => {
    expect(loadRegistry("/nonexistent/targets.json")).toEqual([]);
  });
});
