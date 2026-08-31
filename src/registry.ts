import { readFileSync, existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve, isAbsolute, basename } from "node:path";
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

/**
 * A project built straight from a directory path, with no targets.json.
 *
 * WHY: the first thing a new user types is `npx nocturn-audit scan .`, and
 * that failed with "targets.json not found" -- pointing at a file inside the
 * INSTALLED PACKAGE, which the user cannot reasonably create. A security
 * tool that cannot be run once, on the folder you are standing in, does not
 * get a second try. The registry stays the way to track MANY projects over
 * time; it is no longer the price of admission for scanning one.
 *
 * `url` is deliberately absent: a live probe needs a target the user
 * declared. Ad-hoc scans are static, which is also the safe default --
 * we never fire HTTP at a host nobody named.
 */
export function projeDizinden(dizin: string): Project {
  const absPath = expandPath(dizin);
  if (!existsSync(absPath) || !statSync(absPath).isDirectory()) {
    throw new Error(`Not a directory: ${absPath}`);
  }
  return {
    name: basename(absPath) || absPath,
    path: absPath,
    owned: true,
    stack: discoverStack(absPath),
  } satisfies Project;
}

/** Does this look like a path the user meant, rather than a registry name? */
export function dizinGibiMi(deger: string): boolean {
  if (deger === "." || deger === "..") return true;
  if (deger.startsWith("~") || deger.startsWith("/") || deger.startsWith("./") || deger.startsWith("../")) return true;
  return false;
}
