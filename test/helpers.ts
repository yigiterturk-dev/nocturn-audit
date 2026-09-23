import { ayristir, type AstFile } from "../src/core/ast.js";
import type {
  GrepMatch,
  Project,
  StaticContext,
  Stack,
} from "../src/core/rule.js";

const DEFAULT_STACK: Stack = {
  framework: "next",
  db: "supabase",
  auth: "clerk",
};

/**
 * Builds a fake StaticContext from an in-memory file map.
 * The grep logic matches engine.ts.
 */
export function makeCtx(
  files: Record<string, string>,
  overrides?: {
    project?: Partial<Project>;
    stack?: Partial<Stack>;
    /** Files tracked by git ls-files. When omitted, every file counts as tracked. */
    tracked?: string[];
    /** Is the project a git repository (default true). */
    isGitRepo?: boolean;
  },
): StaticContext {
  const list = Object.keys(files);
  const read = (p: string): string | null =>
    p in files ? files[p] : null;
  const exists = (p: string): boolean => p in files;
  // Bounded read — the real engine reads only the first bytes of the file.
  const readHead = (p: string, bytes = 64 * 1024): string | null => {
    const content = read(p);
    return content === null ? null : content.slice(0, bytes);
  };

  const isGitRepo = overrides?.isGitRepo ?? true;
  const trackedSet =
    overrides?.tracked !== undefined
      ? new Set(overrides.tracked.map((f) => f.replace(/\\/g, "/")))
      : new Set(list.map((f) => f.replace(/\\/g, "/")));
  const isTracked = (p: string): boolean =>
    isGitRepo && trackedSet.has(p.replace(/\\/g, "/"));

  const grep = (
    regex: RegExp,
    include?: (file: string) => boolean,
  ): GrepMatch[] => {
    const matches: GrepMatch[] = [];
    const flags = regex.flags.includes("g") ? regex.flags : regex.flags + "g";
    for (const file of list) {
      if (include && !include(file)) continue;
      const content = files[file];
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const rx = new RegExp(regex.source, flags);
        let m: RegExpExecArray | null;
        while ((m = rx.exec(lines[i])) !== null) {
          matches.push({ file, line: i + 1, column: m.index + 1, text: lines[i] });
          if (m.index === rx.lastIndex) rx.lastIndex++;
        }
      }
    }
    return matches;
  };

  const project: Project = {
    name: overrides?.project?.name ?? "fixture",
    path: overrides?.project?.path ?? "/fixture",
    url: overrides?.project?.url,
    owned: overrides?.project?.owned ?? false,
    stack: { ...DEFAULT_STACK, ...overrides?.stack },
  };

  // A cached tree as in the engine — so rules can call `ctx.ast(file)`.
  const treeCache = new Map<string, AstFile | null>();
  const ast = (p: string): AstFile | null => {
    if (treeCache.has(p)) return treeCache.get(p) ?? null;
    const content = read(p);
    const result = content === null ? null : ayristir(p, content);
    treeCache.set(p, result);
    return result;
  };

  return {
    project,
    root: "/fixture",
    files: list,
    read,
    readHead,
    grep,
    exists,
    isTracked,
    ast,
    isGitRepo,
  };
}
