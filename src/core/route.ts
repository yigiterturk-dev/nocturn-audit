import { cagriAdi, lineNo, ts, type AstFile } from "./ast.js";

/**
 * ROUTE AND IDENTITY ANALYSIS — the shared ground for the access-control rules.
 *
 * "Does this route have auth", "how does this handler read the body", "does this
 * function call an authorisation gate" were answered by three separate rules with
 * three separate regexes — and all three were wrong in different ways:
 *   • a `permissions.includes("orders")` gate went unseen (an IDOR false positive)
 *   • unpublished code under `examples/d1/app/api/...` was mistaken for a route
 *   • auth done at the proxy.ts layer was looked for in the handler
 * Shared ground ends the habit of fixing the same bug in three places.
 */

/** Is this a Next App Router / Pages API route file? ONLY the root app/ and pages/. */
export function isRouteFile(file: string): boolean {
  const f = file.replace(/\\/g, "/");
  // Next routes ONLY the root `app/` (or `src/app/`) directory.
  // A nested app/ such as `examples/d1/app/api/...` is NEVER SERVED.
  if (!/^(?:src\/)?(?:app|pages)\//.test(f)) return false;
  return (
    /(^|\/)app\/.*\/route\.(ts|js|tsx|jsx)$/.test(f) ||
    /(^|\/)pages\/api\/.*\.(ts|js|tsx|jsx)$/.test(f)
  );
}

/** State-changing HTTP methods. */
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export interface Handler {
  metod: string;
  dugum: ts.FunctionDeclaration | ts.VariableDeclaration;
  body: ts.Node;
  line: number;
  writer: boolean;
}

/** Find the exported HTTP handlers (GET/POST/…) in the file. */
export function findHandlers(file: AstFile): Handler[] {
  const bulunan: Handler[] = [];
  const source = file.source;

  const disaAktarilmis = (n: ts.Node): boolean =>
    !!(ts.canHaveModifiers(n) &&
      ts.getModifiers(n)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword));

  const gez = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name && disaAktarilmis(n)) {
      const ad = n.name.text.toUpperCase();
      if (WRITE_METHODS.has(ad) || ad === "GET" || ad === "HEAD" || ad === "OPTIONS") {
        bulunan.push({
          metod: ad,
          dugum: n,
          body: n.body ?? n,
          line: lineNo(file, n),
          writer: WRITE_METHODS.has(ad),
        });
      }
    }
    // export const POST = async (req) => {...}
    if (ts.isVariableStatement(n) && disaAktarilmis(n)) {
      for (const d of n.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !d.initializer) continue;
        const ad = d.name.text.toUpperCase();
        if (!WRITE_METHODS.has(ad) && ad !== "GET") continue;
        if (ts.isArrowFunction(d.initializer) || ts.isFunctionExpression(d.initializer)) {
          bulunan.push({
            metod: ad,
            dugum: d,
            body: d.initializer.body,
            line: lineNo(file, d),
            writer: WRITE_METHODS.has(ad),
          });
        }
      }
    }
    ts.forEachChild(n, gez);
  };
  gez(source);
  return bulunan;
}

/**
 * IDENTITY / AUTHORISATION GATE calls.
 *
 * Not only the `requireX` shape: a permission-list check is a gate too.
 * In one project a `permissions.includes("orders")` went unseen and produced an
 * IDOR false positive.
 */
const KAPI_ADLARI =
  /^(auth|getUser|getSession|getServerSession|currentUser|getToken|getUserRoleData|requireAuth|requireUser|requireAdmin|requireRole|requireOwner|requireMember|requireGate|requirePermission|ensureAuth|assertAdmin|checkAuth|verifyAuth|verifyJwt|verifyToken|verifySession|hasPermission|checkPermission|isAdmin|isAuthenticated|isAuthorized|authorize|guard)$/i;

/** Does this node contain an identity or authorisation gate call? */
export function hasIdentityGate(body: ts.Node): boolean {
  let bulundu = false;
  const gez = (n: ts.Node): void => {
    if (bulundu) return;
    if (ts.isCallExpression(n)) {
      const ad = cagriAdi(n);
      const son = ad.includes(".") ? ad.split(".").pop()! : ad;
      if (KAPI_ADLARI.test(son) || KAPI_ADLARI.test(ad)) {
        bulundu = true;
        return;
      }
      // `permissions.includes("orders")` — a permission-list gate.
      if (
        son === "includes" &&
        ts.isPropertyAccessExpression(n.expression) &&
        /permission|role|yetki|izin|scope/i.test(n.expression.expression.getText())
      ) {
        bulundu = true;
        return;
      }
    }
    ts.forEachChild(n, gez);
  };
  gez(body);
  return bulundu;
}

/**
 * How does the handler read the body? (this determines the CSRF surface)
 *
 * CAREFUL: `Response.json({...})` is WRITING a response, not READING a body. The
 * first version confused the two, and my test enshrined the mistake as correct —
 * a wrong test is worse than wrong code. So only reads from the REQUEST object
 * count: `req.json()`, `request.formData()`.
 */
const ISTEK_ADLARI = /^(req|request|nextReq|nextRequest|r)$/i;

export function bodyShape(body: ts.Node): "json" | "form" | "yok" {
  let bicim: "json" | "form" | "yok" = "yok";
  const gez = (n: ts.Node): void => {
    if (bicim !== "yok") return;
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const nesne = n.expression.expression;
      const istekMi = ts.isIdentifier(nesne) && ISTEK_ADLARI.test(nesne.text);
      if (istekMi) {
        const ad = n.expression.name.text;
        if (ad === "json") bicim = "json";
        else if (ad === "formData" || ad === "text") bicim = "form";
      }
    }
    ts.forEachChild(n, gez);
  };
  gez(body);
  return bicim;
}
