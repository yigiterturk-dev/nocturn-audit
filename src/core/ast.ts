import ts from "typescript";

/**
 * Syntax tree helpers.
 *
 * Regex-based rules got this wrong repeatedly: `new Date()` was read as a DB
 * write, `regex.exec()` as command execution, `select: { status: true }` as a
 * status claim. One cause behind all of them: the rule looks at TEXT, not at
 * the PROGRAM. "What does this call target", "where does this value come from",
 * "which branch is this literal in" cannot be answered with text; on the tree
 * each is a single step.
 * No type checker is created — the whole project is never compiled; each file
 * gets a pure syntax parse. That is enough to answer "which module was this
 * imported from", and it takes milliseconds instead of seconds.
 */

export type AstFile = {
  source: ts.SourceFile;
  /** local name → the module it came from (import and require) */
  ithal: Map<string, { modul: string; disAd: string }>;
};

const DESTEKLI = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/i;

export function ayristirilabilirMi(file: string): boolean {
  return DESTEKLI.test(file);
}

export function ayristir(file: string, content: string): AstFile | null {
  if (!ayristirilabilirMi(file)) return null;
  let source: ts.SourceFile;
  try {
    source = ts.createSourceFile(
      file,
      content,
      ts.ScriptTarget.Latest,
      /* setParentNodes */ true,
      /\.tsx?$/i.test(file) ? ts.ScriptKind.TSX : ts.ScriptKind.JS,
    );
  } catch {
    return null;
  }
  return { source, ithal: ithalatTopla(source) };
}

/** `import { exec as calistir } from "node:child_process"` → calistir → {child_process, exec} */
function ithalatTopla(source: ts.SourceFile): AstFile["ithal"] {
  const harita = new Map<string, { modul: string; disAd: string }>();

  const ekle = (yerel: string, modul: string, disAd: string) =>
    harita.set(yerel, { modul: modul.replace(/^node:/, ""), disAd });

  const gez = (n: ts.Node): void => {
    if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
      const modul = n.moduleSpecifier.text;
      const c = n.importClause;
      if (c?.name) ekle(c.name.text, modul, "default");
      const b = c?.namedBindings;
      if (b && ts.isNamespaceImport(b)) ekle(b.name.text, modul, "*");
      if (b && ts.isNamedImports(b))
        for (const e of b.elements)
          ekle(e.name.text, modul, (e.propertyName ?? e.name).text);
    }
    // const { exec } = require("child_process")  /  const cp = require("...")
    if (ts.isVariableDeclaration(n) && n.initializer && ts.isCallExpression(n.initializer)) {
      const c = n.initializer;
      if (
        ts.isIdentifier(c.expression) &&
        c.expression.text === "require" &&
        c.arguments.length === 1 &&
        ts.isStringLiteral(c.arguments[0])
      ) {
        const modul = c.arguments[0].text;
        if (ts.isIdentifier(n.name)) ekle(n.name.text, modul, "*");
        else if (ts.isObjectBindingPattern(n.name))
          for (const e of n.name.elements)
            if (ts.isIdentifier(e.name))
              ekle(e.name.text, modul, ((e.propertyName as ts.Identifier) ?? e.name).text);
      }
    }
    ts.forEachChild(n, gez);
  };
  gez(source);
  return harita;
}

/** Walk every call expression in the file. */
export function cagrilariGez(
  file: AstFile,
  ziyaret: (cagri: ts.CallExpression | ts.NewExpression) => void,
): void {
  const gez = (n: ts.Node): void => {
    if (ts.isCallExpression(n) || ts.isNewExpression(n)) ziyaret(n);
    ts.forEachChild(n, gez);
  };
  gez(file.source);
}

/** The call's target name: `exec`, `cp.exec`, `re.exec` → "exec" / "cp.exec" / "re.exec" */
export function cagriAdi(cagri: ts.CallExpression | ts.NewExpression): string {
  const e = cagri.expression;
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) {
    const nesne = ts.isIdentifier(e.expression) ? e.expression.text : "?";
    return `${nesne}.${e.name.text}`;
  }
  return "?";
}

/**
 * Does the call resolve to the named export of the named module?
 *
 * `exec(...)` only when imported from `child_process`; `cp.exec(...)` only when
 * `cp` is that module's namespace. `re.exec(...)` (RegExp) and `db.exec(...)`
 * (better-sqlite3) are then eliminated on their own — those two accounted for
 * roughly 100 of the 117 "command execution" findings in one run.
 */
export function moduldenMi(
  file: AstFile,
  cagri: ts.CallExpression | ts.NewExpression,
  modul: string,
  disAdlar: string[],
): boolean {
  const e = cagri.expression;
  if (ts.isIdentifier(e)) {
    const k = file.ithal.get(e.text);
    return !!k && k.modul === modul && disAdlar.includes(k.disAd);
  }
  if (ts.isPropertyAccessExpression(e) && ts.isIdentifier(e.expression)) {
    const k = file.ithal.get(e.expression.text);
    return !!k && k.modul === modul && (k.disAd === "*" || k.disAd === "default")
      ? disAdlar.includes(e.name.text)
      : false;
  }
  return false;
}

/** The node's 1-based line number. */
export function lineNo(file: AstFile, n: ts.Node): number {
  return file.source.getLineAndCharacterOfPosition(n.getStart(file.source)).line + 1;
}

/** The text of the line the node sits on (for evidence). */
export function lineText(file: AstFile, n: ts.Node): string {
  const tam = file.source.getFullText();
  const bas = tam.lastIndexOf("\n", n.getStart(file.source)) + 1;
  const son = tam.indexOf("\n", bas);
  return tam.slice(bas, son === -1 ? undefined : son).trim();
}

/** Is the node inside a catch block? (the failure branch of a measurement) */
export function catchIcinde(n: ts.Node): boolean {
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent)
    if (ts.isCatchClause(p)) return true;
  return false;
}

/** Is the identifier a parameter of the enclosing function? */
export function parametreMi(n: ts.Node, ad: string): boolean {
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent) {
    if (
      ts.isFunctionDeclaration(p) ||
      ts.isFunctionExpression(p) ||
      ts.isArrowFunction(p) ||
      ts.isMethodDeclaration(p)
    ) {
      for (const par of p.parameters)
        if (ts.isIdentifier(par.name) && par.name.text === ad) return true;
    }
  }
  return false;
}

export { ts };

/** The nearest function enclosing the node, if any. */
export function enclosingFunction(n: ts.Node): ts.Node | null {
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent)
    if (
      ts.isFunctionDeclaration(p) ||
      ts.isFunctionExpression(p) ||
      ts.isArrowFunction(p) ||
      ts.isMethodDeclaration(p)
    )
      return p;
  return null;
}

/**
 * Does the function ACTUALLY measure something?
 *
 * If there is an `await` (an external call or IO) or a try/catch, then the
 * constant-looking value the function returns is the result of a MEASUREMENT —
 * a branch label, not a claim. A line window was not enough: in one project the
 * `await` doing the measuring sat 30 lines above the finding, outside a
 * 25-line window.
 */
export function reallyMeasures(fn: ts.Node | null): boolean {
  if (!fn) return false;
  let bulundu = false;
  const gez = (n: ts.Node): void => {
    if (bulundu) return;
    if (ts.isAwaitExpression(n) || ts.isTryStatement(n)) {
      bulundu = true;
      return;
    }
    // Do not descend into nested functions — their measurement is not this one's.
    if (
      n !== fn &&
      (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n))
    )
      return;
    ts.forEachChild(n, gez);
  };
  ts.forEachChild(fn, gez);
  return bulundu;
}

/**
 * Is the node inside a module-level `const`?
 *
 * `const unavailable: Status = { available: false, ... }` is a TEMPLATE value —
 * a named form of the "currently unreachable" state. Reporting it as "hardcoded
 * status" means not reading the variable's name.
 */
export function modulSabitiIcinde(n: ts.Node): boolean {
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent) {
    if (
      ts.isFunctionDeclaration(p) ||
      ts.isFunctionExpression(p) ||
      ts.isArrowFunction(p) ||
      ts.isMethodDeclaration(p)
    )
      return false;
    if (ts.isVariableStatement(p)) return true;
  }
  return false;
}

/** Is the node inside an ORM field-selection object such as `select:` / `include:`? */
export function ormAlanSeciminde(n: ts.Node): boolean {
  const ADLAR = new Set(["select", "include", "omit", "columns", "with", "returning", "set", "orderBy"]);
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent) {
    if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && ADLAR.has(p.name.text))
      return true;
  }
  return false;
}

/**
 * Is this node inside a conditional branch? (when the condition inspects something real)
 *
 * `if (!snapshot?.overview) return { connected: false };` — the constant-looking
 * value is the result of a DECISION. The decision need not be an `await`: the
 * measurement may have happened above and arrived as a parameter (pure summariser
 * functions look exactly like this).
 */
export function isInConditionalBranch(n: ts.Node): boolean {
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent) {
    if (ts.isIfStatement(p) || ts.isConditionalExpression(p)) {
      const kosul = ts.isIfStatement(p) ? p.expression : p.condition;
      // If the condition inspects something (an identifier or access), it is a decision.
      let hasIdentifier = false;
      const gez = (k: ts.Node): void => {
        if (ts.isIdentifier(k) || ts.isPropertyAccessExpression(k)) hasIdentifier = true;
        else ts.forEachChild(k, gez);
      };
      gez(kosul);
      if (hasIdentifier) return true;
    }
    if (ts.isFunctionDeclaration(p) || ts.isFunctionExpression(p) || ts.isArrowFunction(p)) break;
  }
  return false;
}

/**
 * Is the OPPOSITE value of this field also returned in the same function?
 *
 * If `available: true` and `available: false` both appear in one function, the
 * value is a BRANCH OUTCOME rather than a CLAIM: the function also returns its
 * failure paths. One project's PSI summariser was exactly this — `available: false`
 * on lines 177 and 188, `available: true` on line 128.
 *
 * By contrast a one-way object such as `{ serviceReady: true, database: check() }`
 * is still a finding: a hardcoded field sitting next to a measured one is the
 * sneakiest form (half the screen real, half invented).
 */
export function hasOppositeValue(fn: ts.Node | null, ad: string, deger: string): boolean {
  if (!fn) return false;
  let bulundu = false;
  const gez = (n: ts.Node): void => {
    if (bulundu) return;
    if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && n.name.text === ad) {
      const v = n.initializer;
      const text = ts.isStringLiteral(v) ? v.text : v.getText(v.getSourceFile());
      if (text !== deger) {
        bulundu = true;
        return;
      }
    }
    ts.forEachChild(n, gez);
  };
  ts.forEachChild(fn, gez);
  return bulundu;
}

/** Is the node inside a `try` block? */
export function tryIcinde(n: ts.Node): boolean {
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent) {
    if (ts.isTryStatement(p)) return true;
    // Do not cross the function boundary: an outer try does not protect the
    // non-synchronous body of an inner function.
    if (ts.isFunctionDeclaration(p) || ts.isFunctionExpression(p) || ts.isArrowFunction(p))
      return false;
  }
  return false;
}

/**
 * Per line: which lines declare a FUNCTION PARAMETER, and which declare a
 * PROPERTY?
 *
 * The "sensitive data stored in plaintext" rule could not tell them apart and
 * reported `function createAnthropicClient(apiKey: string)` as "apiKey stored in
 * a text column". A parameter is not storage — the value goes INTO the function,
 * it is not written anywhere.
 */
export function parametreVeOzellikSatirlari(file: AstFile): {
  parametre: Set<number>;
  ozellik: Set<number>;
} {
  const parametre = new Set<number>();
  const ozellik = new Set<number>();
  const gez = (n: ts.Node): void => {
    if (ts.isParameter(n)) parametre.add(lineNo(file, n));
    if (
      ts.isPropertyAssignment(n) ||
      ts.isPropertyDeclaration(n) ||
      ts.isPropertySignature(n) ||
      ts.isShorthandPropertyAssignment(n)
    )
      ozellik.add(lineNo(file, n));
    ts.forEachChild(n, gez);
  };
  gez(file.source);
  return { parametre, ozellik };
}

/**
 * Finds an identifier's definition WITHIN THE ENCLOSING FUNCTION.
 *
 * File-wide taint is a disaster in large files: in one project's 6000-line
 * `server.ts`, a single `const url = req.query.x` somewhere made every
 * `redirect(url)` call in the whole file "tainted". Variables are function
 * scoped; taint must be too.
 */
export function kapsamdaTanim(n: ts.Node, ad: string): ts.VariableDeclaration | null {
  let fn: ts.Node | null = enclosingFunction(n);
  let bulunan: ts.VariableDeclaration | null = null;
  const ara = (root: ts.Node): void => {
    const gez = (k: ts.Node): void => {
      if (bulunan) return;
      if (
        ts.isVariableDeclaration(k) &&
        ts.isIdentifier(k.name) &&
        k.name.text === ad &&
        k.initializer
      ) {
        bulunan = k;
        return;
      }
      // Do not descend into inner functions — a same-named binding there is not ours.
      if (
        k !== root &&
        (ts.isFunctionDeclaration(k) || ts.isFunctionExpression(k) || ts.isArrowFunction(k))
      )
        return;
      ts.forEachChild(k, gez);
    };
    ts.forEachChild(root, gez);
  };
  while (fn && !bulunan) {
    ara(fn);
    fn = enclosingFunction(fn);
  }
  return bulunan;
}

/**
 * Is this field defined as a two-state flag ACROSS THE FILE?
 *
 * `interface PsiResult { available: boolean }` plus, in the same file, both `available: true`
 * and `available: false` appear, the field is a STATE FLAG: different code paths
 * return different values for it. Pure transformer functions (`psiFromJson`)
 * return the flag's "success" end; the measurement happened in the caller's
 * fetch.
 *
 * Looking at function scope was not enough: in one project the `available: false`
 * returns lived in a DIFFERENT function (the one doing the fetch), while
 * `available: true` was in the pure transformer. The flag is defined at module
 * level, so the check has to be at module level too.
 */
export function isTwoStateFlag(file: AstFile, ad: string): boolean {
  let tipteBoolean = false;
  const degerler = new Set<string>();
  const gez = (n: ts.Node): void => {
    if (
      ts.isPropertySignature(n) &&
      ts.isIdentifier(n.name) &&
      n.name.text === ad &&
      n.type?.kind === ts.SyntaxKind.BooleanKeyword
    )
      tipteBoolean = true;
    if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && n.name.text === ad) {
      const v = n.initializer;
      if (v.kind === ts.SyntaxKind.TrueKeyword) degerler.add("true");
      if (v.kind === ts.SyntaxKind.FalseKeyword) degerler.add("false");
    }
    ts.forEachChild(n, gez);
  };
  gez(file.source);
  return tipteBoolean && degerler.has("true") && degerler.has("false");
}
