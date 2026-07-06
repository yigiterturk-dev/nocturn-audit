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
 * Bellekteki dosya haritasından sahte bir StaticContext üretir.
 * grep mantığı engine.ts ile aynıdır.
 */
export function makeCtx(
  files: Record<string, string>,
  overrides?: { project?: Partial<Project>; stack?: Partial<Stack> },
): StaticContext {
  const list = Object.keys(files);
  const read = (p: string): string | null =>
    p in files ? files[p] : null;
  const exists = (p: string): boolean => p in files;

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

  return { project, root: "/fixture", files: list, read, grep, exists };
}
