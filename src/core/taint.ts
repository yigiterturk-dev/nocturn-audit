import type { StaticContext } from "./rule.js";
import { ts, type AstFile } from "./ast.js";

/**
 * CROSS-FILE TAINT.
 *
 * The old rules asked "is there an input hint within a few lines of the sink?"
 * — a window heuristic. It misses the common shape where the value is built in
 * one function and consumed in another, and it fires on unrelated input nearby.
 *
 * This builds a per-project index of TAINT SOURCES: functions whose body reads
 * request/user data. A call to such a function is tainted even when the call
 * site shows no `req.` at all. Sanitizers (functions whose name says they
 * escape/validate) are tracked so a tainted value that passes through one is
 * not reported.
 */

const INPUT_RE =
  /(req\.|request\.|params|searchParams|query\.|body|formData|input|\.get\(|nextUrl|userInput|payload|searchParams|await\s+request)/i;

const SANITIZER_RE =
  /(sanitize|escape|allowlist|isSafe|\bsafe|validate|normalize|basename|resolve|purify)/i;

export interface TaintIndex {
  sources: Set<string>;
  sanitizers: Set<string>;
}

function fnName(n: ts.Node): string | null {
  if (ts.isFunctionDeclaration(n) && n.name) return n.name.text;
  if (ts.isFunctionExpression(n) && n.name) return n.name.text;
  if (ts.isArrowFunction(n)) {
    let p: ts.Node | undefined = n.parent;
    while (p) {
      if (ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
      p = p.parent;
    }
  }
  return null;
}

/** Scan every file once and index which functions read user input. */
export function buildTaintIndex(ctx: StaticContext): TaintIndex {
  const sources = new Set<string>();
  const sanitizers = new Set<string>();
  for (const file of ctx.files) {
    const ast = ctx.ast(file);
    if (!ast) continue;
    const gez = (n: ts.Node): void => {
      if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n)) {
        const name = fnName(n);
        if (name) {
          const body = n.getText(ast.source);
          if (INPUT_RE.test(body)) sources.add(name);
          if (SANITIZER_RE.test(name)) sanitizers.add(name);
        }
      }
      ts.forEachChild(n, gez);
    };
    gez(ast.source);
  }
  return { sources, sanitizers };
}

/**
 * Is the expression tainted by user input? Resolves:
 *  1. direct request access in the text,
 *  2. a call to a known taint source (cross-file),
 *  3. a local `const x = <rhs>` definition (one level),
 *  4. a call to a sanitizer → NOT tainted.
 */
export function isTainted(
  ast: AstFile,
  node: ts.Node,
  index: TaintIndex,
  depth = 0,
): boolean {
  if (depth > 3) return false;
  const text = node.getText(ast.source);
  if (INPUT_RE.test(text)) return true;

  if (ts.isCallExpression(node)) {
    const callee = node.expression;
    if (ts.isIdentifier(callee)) {
      if (index.sanitizers.has(callee.text)) return false;
      if (index.sources.has(callee.text)) return true;
    }
    for (const a of node.arguments) {
      if (isTainted(ast, a, index, depth + 1)) return true;
    }
    return false;
  }

  if (ts.isIdentifier(node)) {
    const m = new RegExp(
      `(?:const|let|var)\\s+${node.text}\\s*=\\s*([^;\\n]+)`,
    ).exec(ast.source.getFullText());
    if (m) {
      const rhs = m[1].trim();
      // A sanitizer wrapping the value wins over the raw input text inside it:
      // `safePath(req.query.file)` is NOT tainted even though it mentions req.
      const call = rhs.match(/^([A-Za-z_$][\w$]*)\s*\(/);
      if (call) {
        if (index.sanitizers.has(call[1])) return false;
        if (index.sources.has(call[1])) return true;
      }
      if (INPUT_RE.test(rhs)) return true;
    }
    return false;
  }

  return false;
}
