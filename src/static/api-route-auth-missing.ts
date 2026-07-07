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
  // ek auth/yetki sinyalleri (FP azaltma)
  /getToken\s*\(/,
  /\bjwt\.verify\s*\(/,
  /\bbearer\b/i,
  /authorization/i,
  /CRON_SECRET/,
  /process\.env\.\w*(SECRET|TOKEN|API_KEY)\b[\s\S]{0,80}(===|==|!==|!=|includes|timingSafeEqual)/i,
  /isAdmin|isAuthenticated|isAuthorized|authorize\b|requireAuth|requireAdmin|requireUser|requireGate|ensureAuth|checkAuth|guard/i,
];

// Handler'da DB'ye dokunulduğuna dair işaretler — bu olmadan route büyük olasılıkla
// public (og görsel, health, redirect, proxy) olduğundan bulgu üretmeyiz.
const DB_ACCESS =
  /(prisma\.|\bdb\.|drizzle|mongoose|sequelize|\bknex\b|supabase[\s\S]{0,40}\.from\(|\.from\(["'`]?\w|\.query\s*\(|sql`|\.findMany\(|\.findUnique\(|\.findFirst\(|\.insert\(|\.update\(|\.delete\(|\.create\(|\.upsert\(|\.collection\()/i;

const isApiRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/");
  return (
    /(^|\/)app\/.*\/route\.(ts|js|tsx|jsx)$/.test(f) ||
    /(^|\/)pages\/api\/.*\.(ts|js|tsx|jsx)$/.test(f)
  );
};

// Auth ÜRETEN (tüketmeyen) sınır route'ları — login/register/callback vb. tasarımı
// gereği public olmalı; burada auth aramak yanlış.
const isAuthBoundaryRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/").toLowerCase();
  return /\/(login|log-in|signin|sign-in|register|signup|sign-up|logout|sign-out|forgot-password|reset-password|verify-email|magic-link|callback|oauth)\b/.test(
    f,
  );
};

// Public form ucu mu? rate-limit + input validation var VE yalnızca insert/notify
// yapıyor (kullanıcıya-ait kaynak okumuyor) → lead/newsletter/iletişim formu.
const looksLikePublicForm = (content: string): boolean => {
  const hasRateLimit =
    /rateLimit|rate_limit|enforceWriteLimit|ratelimit|Ratelimit|limiter\.|@upstash\/ratelimit|checkRateLimit/i.test(
      content,
    );
  // Zod/yup/joi ŞEMA doğrulaması VEYA elle giriş doğrulaması / double opt-in sinyalleri.
  const hasValidation =
    /\.safeParse\(|z\.object\(|zodResolver|yup\.|joi\.|\.parse\(|EMAIL_RE|signOptIn|opt-?in|double[_-]?opt|confirmation|sanitize|\bvalidate\b|RE\.test\(/i.test(
      content,
    );
  // Yalnızca insert/upsert/create yapıyor (kullanıcıya-ait kaynak okumuyor).
  const insertOnly = /\.(create|upsert|insert|createMany)\s*\(/i.test(content);
  // Kullanıcıya-ait kaynak OKUMA (ownership yüzeyi) yoksa güvenli-public sayılır.
  const readsUserData =
    /\.(findUnique|findFirst|findMany)\s*\(|\.select\s*\([\s\S]{0,60}(user_id|owner)/i.test(
      content,
    );
  return hasRateLimit && hasValidation && insertOnly && !readsUserData;
};

// Konvansiyonel olarak public olan route'lar — auth beklenmez, FP üretmeyelim.
const isPublicByConvention = (file: string, content: string): boolean => {
  const f = file.replace(/\\/g, "/").toLowerCase();
  // Auth sınırı (login/register/callback) → public zorunlu.
  if (isAuthBoundaryRoute(file)) return true;
  // rate-limit + validation'lı public form (lead/newsletter/iletişim).
  if (looksLikePublicForm(content)) return true;
  // Sağlık/durum, sitemap/robots/manifest, og/görsel uçları.
  if (/\/(health|healthz|status|ping|readyz|livez)\//.test(f)) return true;
  if (/\/(sitemap|robots|manifest)\b/.test(f)) return true;
  if (/\/(og|opengraph-image|twitter-image|icon|apple-icon|favicon)\b/.test(f))
    return true;
  if (/ImageResponse|new\s+ImageResponse/.test(content)) return true;
  // NextAuth / Clerk / auth sağlayıcı catch-all handler'ları.
  if (/\[\.\.\.(nextauth|clerk|auth|kinde|betterauth)\]/.test(f)) return true;
  if (/\bNextAuth\s*\(|toNextJsHandler|createRouteHandler|handlers\s*\}/.test(content))
    return true;
  // Webhook uçları imza doğrulaması ile — auth kural kapsamı değil (webhook-signature ayrı kural).
  if (
    /webhook|\/callback\//.test(f) &&
    /(constructEvent|svix|Webhook\(|wh\.verify|x-hub-signature|stripe-signature|timingSafeEqual|createHmac|verifySignature|verifyWebhook)/i.test(
      content,
    )
  )
    return true;
  return false;
};

const HANDLER_RE =
  /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=/;
const MUTATION_RE =
  /export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=/;

export const apiRouteAuthMissing: StaticRule = {
  id: "a01-api-route-auth-missing",
  title: "API route'unda kimlik doğrulama kontrolü yok",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "static",
  // Sezgisel: birçok route tasarım gereği public'tir (webhook/health/public GET).
  confidence: "olası",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!isApiRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      if (!HANDLER_RE.test(content)) continue;
      if (AUTH_HINTS.some((re) => re.test(content))) continue;
      if (isPublicByConvention(file, content)) continue;
      // DB'ye dokunmayan route'lar çoğunlukla public/yardımcı — yüksek FP; atla.
      if (!DB_ACCESS.test(content)) continue;

      const isMutation = MUTATION_RE.test(content);

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
        // Yalnızca DB'ye YAZAN (mutation) korumasız handler yüksek; salt-okuma (public
        // olabilir) düşük — kesin IDOR/leak kanıtı olmadan yükseltmiyoruz.
        severity: isMutation ? "high" : "low",
        confidence: "olası",
        description: isMutation
          ? "Bu API route veritabanına yazan bir mutation handler (POST/PUT/PATCH/DELETE) tanımlıyor ama içinde tanınabilir bir auth/oturum kontrolü yok. Yetkisiz veri değişikliğine açık olabilir."
          : "Bu API route veritabanına erişen bir handler tanımlıyor ama içinde tanınabilir bir auth/oturum kontrolü yok. Veri public değilse yetkisiz okumaya açık olabilir (public veri sunuyorsa göz ardı edilebilir).",
        evidence: [fileEvidence(file, line, snippet)],
        remediation:
          "Handler başında oturum/kullanıcı doğrulaması yapın (Clerk auth(), Supabase getUser(), getServerSession vb.) ve yetkisizse 401/403 dönün. Uç gerçekten public ise bunu açıkça belgeleyin.",
      });
    }
    return findings;
  },
};
