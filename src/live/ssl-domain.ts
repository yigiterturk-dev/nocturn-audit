import tls from "node:tls";
import { lookup } from "node:dns/promises";
import type { Finding } from "../core/finding.js";
import { httpEvidence } from "../core/finding.js";
import type { LiveContext, LiveRule } from "../core/rule.js";

/** Ağ ilkelleri — testlerde sahtelenebilir (deterministik/çevrimdışı). */
export interface SslDomainHooks {
  dnsLookup(host: string): Promise<unknown>;
  fetchCert(host: string): Promise<CertInfo>;
}

/**
 * A05 (canlı) — SSL sertifikası + alan adı (domain) sağlığı.
 *
 * Owned:true kapısı motor tarafından uygulanır. Yıkıcı değil: tek TLS el sıkışması,
 * DNS lookup ve HTTP yönlendirme kontrolü. Sertifika son kullanma tarihi
 * deterministiktir → "kesin". DNS/yönlendirme sezgisel → "olası".
 */

export interface CertInfo {
  validTo?: string;
  error?: string;
}

/** 443 portuna tek TLS el sıkışması yapıp peer sertifikasını (valid_to) okur. */
function fetchCert(host: string, timeoutMs = 10_000): Promise<CertInfo> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (info: CertInfo) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {
        /* yoksay */
      }
      resolve(info);
    };
    // rejectUnauthorized:false → süresi geçmiş / uyumsuz sertifikada dahi
    // sertifikayı okuyup DEĞERLENDİREBİLMEK için (kendimiz karar veririz).
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: false, timeout: timeoutMs },
      () => {
        const cert = socket.getPeerCertificate();
        finish({ validTo: cert?.valid_to });
      },
    );
    socket.on("timeout", () => finish({ error: "TLS el sıkışması zaman aşımı" }));
    socket.on("error", (e) => finish({ error: e instanceof Error ? e.message : String(e) }));
  });
}

/** baseUrl'den hostname çıkar. */
function hostnameOf(baseUrl: string): string | null {
  try {
    return new URL(baseUrl).hostname || null;
  } catch {
    return null;
  }
}

const RULE_ID = "a05-live-ssl-domain";
const RULE_OWASP = "A05:2021-Security Misconfiguration" as const;

const DEFAULT_HOOKS: SslDomainHooks = {
  dnsLookup: (host) => lookup(host),
  fetchCert: (host) => fetchCert(host),
};

/**
 * Kural gövdesi (test kancalarıyla). `run` bunu gerçek DNS/TLS ilkelleriyle çağırır;
 * testler mock ilkellerle çağırıp ağa çıkmadan doğrular.
 */
export async function evaluateSslDomain(
  ctx: LiveContext,
  hooks: SslDomainHooks = DEFAULT_HOOKS,
): Promise<Finding[]> {
    const findings: Finding[] = [];
    const host = hostnameOf(ctx.baseUrl);
    if (!host) return findings;
    const isHttps = ctx.baseUrl.startsWith("https://");
    const self = { id: RULE_ID, owasp: RULE_OWASP };

    // --- 1) DNS çözümlemesi ---
    try {
      await hooks.dnsLookup(host);
    } catch {
      findings.push({
        ruleId: self.id,
        title: `DNS çözülemedi: ${host}`,
        owasp: self.owasp,
        severity: "medium",
        confidence: "olası",
        description: `${host} için DNS A/AAAA kaydı çözülemedi. Alan adı süresi dolmuş, DNS yanlış yapılandırılmış ya da geçici bir kesinti olabilir.`,
        evidence: [httpEvidence(`DNS lookup ${host}`, "NXDOMAIN / çözülemedi")],
        remediation:
          "Alan adı kaydının aktif olduğunu ve DNS sağlayıcısında doğru A/CNAME kayıtlarının bulunduğunu doğrulayın.",
      });
      // DNS yoksa TLS/redirect anlamsız — erken dön.
      return findings;
    }

    // --- 2) TLS sertifika son kullanma tarihi (yalnızca https) ---
    if (isHttps) {
      const cert = await hooks.fetchCert(host);
      if (cert.validTo) {
        const expiry = new Date(cert.validTo).getTime();
        if (Number.isFinite(expiry)) {
          const days = Math.floor((expiry - Date.now()) / 86_400_000);
          if (days < 0) {
            findings.push({
              ruleId: self.id,
              title: `SSL sertifikası süresi DOLMUŞ: ${host}`,
              owasp: self.owasp,
              severity: "critical",
              confidence: "kesin",
              cwe: "CWE-298",
              description: `${host} TLS sertifikasının süresi ${Math.abs(days)} gün önce doldu (valid_to: ${cert.validTo}). Ziyaretçiler tarayıcı güvenlik uyarısı görür.`,
              evidence: [httpEvidence(`TLS ${host}:443`, `valid_to: ${cert.validTo}`)],
              remediation:
                "Sertifikayı hemen yenileyin. Let's Encrypt/hosting otomatik yenilemesinin çalıştığından emin olun.",
            });
          } else if (days < 7) {
            findings.push({
              ruleId: self.id,
              title: `SSL sertifikası ${days} gün içinde bitiyor: ${host}`,
              owasp: self.owasp,
              severity: "critical",
              confidence: "kesin",
              cwe: "CWE-298",
              description: `${host} TLS sertifikası ${days} gün içinde (valid_to: ${cert.validTo}) sona eriyor. Yenileme başarısız olursa site erişilemez hâle gelir.`,
              evidence: [httpEvidence(`TLS ${host}:443`, `valid_to: ${cert.validTo}`)],
              remediation:
                "Sertifika yenilemesini şimdi tetikleyin / otomatik yenilemeyi doğrulayın.",
            });
          } else if (days < 30) {
            findings.push({
              ruleId: self.id,
              title: `SSL sertifikası ${days} gün içinde bitiyor: ${host}`,
              owasp: self.owasp,
              severity: "high",
              confidence: "kesin",
              cwe: "CWE-298",
              description: `${host} TLS sertifikası ${days} gün içinde (valid_to: ${cert.validTo}) sona eriyor. Otomatik yenileme yoksa planlayın.`,
              evidence: [httpEvidence(`TLS ${host}:443`, `valid_to: ${cert.validTo}`)],
              remediation: "Sertifika yenilemesini planlayın / otomatik yenilemeyi doğrulayın.",
            });
          }
        }
      }
    }

    // --- 3) HTTP → HTTPS yönlendirmesi + yönlendirme zinciri uzunluğu ---
    if (isHttps) {
      const httpProbe = await ctx.probe(`http://${host}/`);
      if (httpProbe.ok) {
        const loc = httpProbe.headers["location"] ?? "";
        const redirectsToHttps =
          httpProbe.status >= 300 &&
          httpProbe.status < 400 &&
          /^https:\/\//i.test(loc);
        if (httpProbe.status === 200) {
          // HTTP düz 200 döndü — HTTPS'e yönlendirme yok.
          findings.push({
            ruleId: self.id,
            title: `HTTP, HTTPS'e yönlendirmiyor: ${host}`,
            owasp: self.owasp,
            severity: "medium",
            confidence: "olası",
            cwe: "CWE-319",
            description: `http://${host}/ isteği 200 döndü ve HTTPS'e yönlendirmedi. Trafik şifrelenmemiş taşınabilir (SSL-stripping riski).`,
            evidence: [httpEvidence(httpProbe.requestLine, httpProbe.responseLine)],
            remediation:
              "Tüm HTTP isteklerini kalıcı olarak (301) HTTPS'e yönlendirin ve HSTS ekleyin.",
          });
        } else if (httpProbe.status >= 300 && httpProbe.status < 400 && !redirectsToHttps) {
          findings.push({
            ruleId: self.id,
            title: `HTTP yönlendirmesi HTTPS'e değil: ${host}`,
            owasp: self.owasp,
            severity: "low",
            confidence: "olası",
            cwe: "CWE-319",
            description: `http://${host}/ yönlendiriyor ama hedef HTTPS değil (Location: ${loc || "?"}).`,
            evidence: [httpEvidence(httpProbe.requestLine, httpProbe.responseLine)],
            remediation: "HTTP → HTTPS 301 yönlendirmesini doğrulayın.",
          });
        }
      }
    }

    // --- 4) Yönlendirme zinciri uzunluğu (/ üzerinden) ---
    let current = "/";
    let hops = 0;
    const seen = new Set<string>();
    const chain: string[] = [];
    while (hops < 8) {
      const r = await ctx.probe(current);
      if (!r.ok) break;
      chain.push(`${r.status} ${r.url}`);
      if (r.status >= 300 && r.status < 400) {
        const loc = r.headers["location"];
        if (!loc || seen.has(loc)) break;
        seen.add(loc);
        current = loc;
        hops++;
      } else {
        break;
      }
    }
    if (hops >= 4) {
      findings.push({
        ruleId: self.id,
        title: `Uzun yönlendirme zinciri (${hops} atlama): ${host}`,
        owasp: self.owasp,
        severity: "low",
        confidence: "olası",
        description: `Kök URL ${hops} yönlendirme atlaması içeriyor. Uzun zincirler gecikme yaratır ve yönlendirme döngüsü/yapılandırma hatası işareti olabilir.`,
        evidence: [httpEvidence(`GET ${ctx.baseUrl}/`, chain.join("\n"))],
        remediation:
          "Yönlendirme sayısını azaltın; www/HTTPS/locale yönlendirmelerini tek adımda birleştirin.",
      });
    }

    return findings;
}

export const liveSslDomain: LiveRule = {
  id: RULE_ID,
  title: "Canlı: SSL sertifikası / domain sağlığı",
  owasp: RULE_OWASP,
  severity: "high",
  kind: "live",
  run(ctx): Promise<Finding[]> {
    return evaluateSslDomain(ctx);
  },
};
