import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveRule } from "../core/rule.js";

/**
 * A03 (canlı) — Yansıyan girdi probu (non-destructive).
 * Zararsız benzersiz bir işaretleyici query'de gönderilir; yanıtta HTML-encode
 * EDİLMEDEN aynen yansırsa reflected-XSS ihtimali işaretlenir. Payload çalıştırıcı değil.
 */

const MARKER = "nctrn__probe__7q1";
// zararsız ama encode edilirse fark edilir bir işaretleyici
const RAW = `${MARKER}<z>"'`;

export const liveReflectedXss: LiveRule = {
  id: "a03-live-reflected-input",
  title: "Canlı: yansıyan (encode edilmeyen) girdi — olası XSS",
  owasp: "A03:2021-Injection",
  severity: "medium",
  kind: "live",
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = [];
    const q = encodeURIComponent(RAW);
    const paths = [`/?q=${q}`, `/search?q=${q}`];
    for (const path of paths) {
      const res = await ctx.probe(path);
      if (!res.ok || res.status !== 200) continue;
      const ct = res.headers["content-type"] ?? "";
      if (!/html/.test(ct)) continue;
      const body = res.bodySnippet;
      // ham < > yansıması var mı (encode edilmemiş)
      const rawReflected = body.includes(`${MARKER}<z>`);
      const encodedReflected =
        body.includes(`${MARKER}&lt;z&gt;`) || body.includes(MARKER + "%3C");
      if (rawReflected && !encodedReflected) {
        findings.push({
          ruleId: this.id,
          title: "Girdi HTML-encode edilmeden yansıyor",
          owasp: this.owasp,
          severity: "high",
          description:
            "Gönderilen işaretleyici (< > karakterleriyle) yanıt gövdesinde encode edilmeden yansıdı. Yansıyan XSS ihtimali yüksek. (Non-destructive prob — manuel doğrulayın.)",
          evidence: [
            httpEvidence(
              res.requestLine,
              `HTTP ${res.status}\n…${body.slice(Math.max(0, body.indexOf(MARKER) - 20), body.indexOf(MARKER) + 40)}…`,
            ),
          ],
          remediation:
            "Kullanıcı girdisini çıktıda HTML-encode edin; framework'ün otomatik kaçışını kullanın, dangerouslySetInnerHTML'den kaçının, CSP ekleyin.",
        });
      } else if (rawReflected === false && body.includes(MARKER)) {
        // encode edilmiş yansıma = güvenli, bulgu yok
      }
    }
    return findings;
  },
};
