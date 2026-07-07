import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticContext, StaticRule } from "../core/rule.js";

/**
 * A01 — Durum değiştiren rotalarda CSRF koruması yok.
 *
 * Cookie/oturum tabanlı kimlik doğrulama kullanan POST/PUT/PATCH/DELETE handler'larında
 * CSRF token doğrulaması görülmüyorsa işaretler. (Bearer/Authorization header tabanlı
 * API'ler ve imzalı webhook'lar CSRF'e açık olmadığından hariç tutulur.)
 */

const MUTATING_HANDLER =
  /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|(?:^|\s)(POST|PUT|PATCH|DELETE)\s*:\s*(?:async\s*)?\(|req\.method\s*===?\s*["'`](POST|PUT|PATCH|DELETE)["'`]/;

// Cookie/oturum tabanlı kimlik (CSRF riski buradadır).
const COOKIE_SESSION =
  /\bcookies\(\)|req\.cookies|request\.cookies|getServerSession|next-auth|getToken\s*\(|iron-session|express-session|\bsession\.user\b/i;

// Token/Bearer tabanlı → CSRF'e açık değil.
const TOKEN_AUTH =
  /Authorization["'`\s:]|Bearer\s|x-api-key|apiKey\s*header|headers\.get\(\s*["'`]authorization/i;

// CSRF koruması göstergeleri.
const CSRF_GUARD =
  /csrf|xsrf|x-csrf-token|verifyCsrf|csrfToken|__Host-|double[_-]?submit|origin\s*check|verifyOrigin|assertOrigin/i;

// İmzalı webhook → hariç.
const WEBHOOK =
  /webhook|constructEvent|stripe-signature|svix|x-hub-signature|verifySignature/i;

const isApiRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /\/route\.(ts|js)$/.test(f) ||
    /\/api\//.test(f) ||
    /pages\/api\//.test(f) ||
    /actions?\.(ts|js)$/.test(f)
  );
};

export const csrfMissing: StaticRule = {
  id: "a01-csrf-missing",
  title: "Durum değiştiren rotada CSRF koruması yok",
  owasp: "A01:2021-Broken Access Control",
  severity: "medium",
  cwe: "CWE-352",
  kind: "static",
  run(ctx: StaticContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (/(test|spec|__tests__|fixtures?)/.test(file)) continue;
      if (!isApiRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      if (WEBHOOK.test(content)) continue;
      if (!MUTATING_HANDLER.test(content)) continue;
      if (!COOKIE_SESSION.test(content)) continue; // sadece cookie/oturum tabanlı
      if (TOKEN_AUTH.test(content)) continue; // Bearer/token → CSRF'e kapalı
      if (CSRF_GUARD.test(content)) continue; // koruma var

      // handler satırını bul
      const lines = content.split(/\r?\n/);
      let line = 1;
      let snippet = "";
      for (let i = 0; i < lines.length; i++) {
        if (MUTATING_HANDLER.test(lines[i])) {
          line = i + 1;
          snippet = lines[i];
          break;
        }
      }

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "medium",
        cwe: this.cwe,
        description:
          "Cookie/oturum tabanlı kimlik doğrulama kullanan durum değiştiren bir handler (POST/PUT/PATCH/DELETE) CSRF token doğrulaması yapmıyor gibi görünüyor. Saldırgan, kurbanın oturum cookie'siyle sahte istek tetikleyebilir.",
        evidence: [fileEvidence(file, line, snippet || "mutating handler")],
        remediation:
          "CSRF token doğrulaması ekleyin (double-submit cookie veya sunucu-üretimli token). SameSite=Lax/Strict cookie kullanın ve/veya Origin/Referer başlığını doğrulayın. Mümkünse cookie yerine Authorization: Bearer token kullanın.",
        remediationCode:
          "const origin = req.headers.get('origin');\n" +
          "if (origin && new URL(origin).host !== req.headers.get('host')) {\n" +
          "  return new Response('CSRF', { status: 403 });\n" +
          "}",
      });
    }
    return findings;
  },
};
