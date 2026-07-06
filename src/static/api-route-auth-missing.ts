import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A01 — API route'unda auth kontrolü yok.
 * app/api/**\/route.ts ve pages/api/** dosyalarında yazma/okuma yapan handler'lar
 * içinde bilinen auth kontrol paternlerinden hiçbiri geçmiyorsa bulgu.
 */

const AUTH_HINTS = [
  /\bauth\s*\(/i,
  /getServerSession/,
  /currentUser\s*\(/,
  /auth\(\)/,
  /getUser\s*\(/,
  /getSession/,
  /clerkClient/,
  /requireUser/,
  /verify(Jwt|Token|Auth|Session)/i,
  /\bsession\b/,
  /supabase[\s\S]{0,40}\.auth\./,
  /x-api-key/i,
  /unstable_getServerSession/,
  /withApiAuth/,
];

const isApiRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /(^|\/)app\/.*\/route\.(ts|js|tsx|jsx)$/.test(f) ||
    /(^|\/)pages\/api\/.*\.(ts|js|tsx|jsx)$/.test(f)
  );
};

// mutasyon / veri çeken handler var mı — boş/statik route'ları elemek için
const HANDLER_RE =
  /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=/;

export const apiRouteAuthMissing: StaticRule = {
  id: "a01-api-route-auth-missing",
  title: "API route'unda kimlik doğrulama kontrolü yok",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!isApiRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      if (!HANDLER_RE.test(content)) continue;
      const hasAuth = AUTH_HINTS.some((re) => re.test(content));
      if (hasAuth) continue;

      // handler satırını kanıt olarak bul
      const lines = content.split(/\r?\n/);
      let line = 1;
      let snippet = lines[0] ?? "";
      for (let i = 0; i < lines.length; i++) {
        if (HANDLER_RE.test(lines[i])) {
          line = i + 1;
          snippet = lines[i];
          break;
        }
      }
      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "high",
        description:
          "Bu API route bir HTTP handler tanımlıyor ama içinde tanınabilir bir auth/oturum kontrolü yok. Yetkisiz erişime açık olabilir.",
        evidence: [fileEvidence(file, line, snippet)],
        remediation:
          "Handler başında oturum/kullanıcı doğrulaması yapın (Clerk auth(), Supabase getUser(), getServerSession vb.) ve yetkisizse 401/403 dönün.",
      });
    }
    return findings;
  },
};
