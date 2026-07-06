import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A01 (canlı) — Auth'suz açılan hassas uçlar (/admin gibi).
 * Non-destructive: sadece GET, kimlik göndermeden. 200 + auth-değil işareti aranır.
 */

const PATHS = ["/admin", "/dashboard/admin", "/api/admin", "/api/users"];

// yanıt bir login/redirect değil, gerçek içerik mi
const looksProtected = (status: number, body: string, headers: Record<string, string>): boolean => {
  if ([301, 302, 303, 307, 308].includes(status)) {
    const loc = (headers["location"] ?? "").toLowerCase();
    if (/login|signin|sign-in|auth|clerk|accounts\./.test(loc)) return true;
  }
  if ([401, 403].includes(status)) return true;
  if (status === 404) return true;
  if (/(sign in|log in|giriş yap|unauthorized|yetkisiz|please authenticate)/i.test(body))
    return true;
  return false;
};

export const liveOpenEndpoints: LiveRule = {
  id: "a01-live-open-admin-endpoints",
  title: "Canlı: kimlik doğrulamasız erişilebilen hassas uç",
  owasp: "A01:2021-Broken Access Control",
  severity: "high",
  kind: "live",
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const path of PATHS) {
      const res = await ctx.probe(path);
      if (!res.ok) continue;
      if (res.status !== 200) continue;
      if (looksProtected(res.status, res.bodySnippet, res.headers)) continue;

      findings.push({
        ruleId: this.id,
        title: `Kimlik doğrulamasız erişim: ${path}`,
        owasp: this.owasp,
        severity: "high",
        description: `${path} kimlik göndermeden 200 döndü ve içerik bir login/redirect'e benzemiyor. Yetki kontrolü eksik olabilir. (Manuel doğrulama önerilir.)`,
        evidence: [
          httpEvidence(
            res.requestLine,
            `HTTP ${res.status} ${res.statusText}\n${res.bodySnippet.slice(0, 160)}`,
          ),
        ],
        remediation:
          "Bu ucu middleware/route seviyesinde auth ile koruyun; yetkisiz istekleri 401/403 döndürün veya login'e yönlendirin.",
      });
    }
    return findings;
  },
};
