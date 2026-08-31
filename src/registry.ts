import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve, isAbsolute } from "node:path";
import type { Project, Stack } from "./core/rule.js";

interface RawProject {
  name: string;
  path: string;
  url?: string;
  owned?: boolean;
  stack?: Partial<Stack>;
}

interface RawTargets {
  projects: RawProject[];
}

/** Expand a ~/... path to an absolute one. */
export function expandPath(p: string): string {
  if (p.startsWith("~")) {
    return join(homedir(), p.slice(1).replace(/^[/\\]/, ""));
  }
  return isAbsolute(p) ? p : resolve(p);
}

/**
 * package.json + dosya paternlerinden stack tahmini yap.
 * Fills in fields missing from targets.json.
 */
export function discoverStack(root: string, provided?: Partial<Stack>): Stack {
  const stack: Stack = {
    framework: provided?.framework,
    db: provided?.db,
    auth: provided?.auth,
  };

  let pkg: Record<string, unknown> = {};
  const pkgPath = join(root, "package.json");
  if (existsSync(pkgPath)) {
    try {
      pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    } catch {
      pkg = {};
    }
  }
  const deps: Record<string, string> = {
    ...((pkg.dependencies as Record<string, string>) ?? {}),
    ...((pkg.devDependencies as Record<string, string>) ?? {}),
  };
  const has = (name: string) => name in deps;

  // Framework
  if (!stack.framework) {
    if (has("next")) stack.framework = "next";
    else if (has("vite")) stack.framework = "vite";
    else if (
      existsSync(join(root, "next.config.js")) ||
      existsSync(join(root, "next.config.mjs")) ||
      existsSync(join(root, "next.config.ts"))
    )
      stack.framework = "next";
    else if (
      existsSync(join(root, "vite.config.js")) ||
      existsSync(join(root, "vite.config.ts"))
    )
      stack.framework = "vite";
    else if (existsSync(pkgPath)) stack.framework = "node";
    else stack.framework = "unknown";
  }

  // DB
  if (!stack.db) {
    if (has("@supabase/supabase-js") || has("@supabase/ssr"))
      stack.db = "supabase";
    else if (has("@neondatabase/serverless")) stack.db = "neon";
    else if (has("@prisma/client") || has("prisma")) stack.db = "prisma";
    else if (has("pg") || has("postgres")) stack.db = "postgres";
    else stack.db = "unknown";
  }

  // Auth
  if (!stack.auth) {
    if (has("@clerk/nextjs") || has("@clerk/clerk-react") || has("@clerk/clerk-sdk-node"))
      stack.auth = "clerk";
    else if (has("next-auth") || has("@auth/core")) stack.auth = "next-auth";
    else if (has("@supabase/supabase-js") && !has("@clerk/nextjs"))
      stack.auth = "supabase";
    else stack.auth = "unknown";
  }

  return stack;
}

/**
 * Reads targets.json, expands paths, and detects a missing stack.
 * Returns an empty list when the file is absent (the CLI warns about it).
 */
export function loadRegistry(targetsPath: string): Project[] {
  if (!existsSync(targetsPath)) {
    return [];
  }
  let raw: RawTargets;
  try {
    raw = JSON.parse(readFileSync(targetsPath, "utf8"));
  } catch (err) {
    throw new Error(
      `Could not read targets.json (${targetsPath}): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!raw.projects || !Array.isArray(raw.projects)) {
    throw new Error("targets.json must contain a 'projects' array.");
  }

  return raw.projects.map((p) => {
    const absPath = expandPath(p.path);
    const stack = discoverStack(absPath, p.stack);
    return {
      name: p.name,
      path: absPath,
      url: p.url,
      owned: p.owned === true,
      stack,
    } satisfies Project;
  });
}

export function findProject(
  projects: Project[],
  name: string,
): Project | undefined {
  return projects.find(
    (p) => p.name.toLowerCase() === name.toLowerCase(),
  );
}
