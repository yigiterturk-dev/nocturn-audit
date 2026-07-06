import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A08 — Doğrulanmamış webhook.
 * Stripe/iyzico/Meta/GitHub webhook route'unda imza doğrulaması yok.
 */

const isWebhookRoute = (file: string): boolean => {
  const f = file.replace(/\\/g, "/").toLowerCase();
  return (
    /(webhook|callback|ipn)/.test(f) &&
    (/(app\/.*\/route\.(ts|js))/.test(f) || /(pages\/api\/)/.test(f))
  );
};

const PROVIDER = /(stripe|iyzico|iyzipay|meta|facebook|whatsapp|paddle|lemonsqueezy|github|shopify|clerk)/i;

const SIGNATURE_VERIFY =
  /(constructEvent|verifyWebhookSignature|verifySignature|X-Hub-Signature|stripe-signature|Webhook-Signature|createHmac|timingSafeEqual|svix|Webhook\()/i;

export const webhookSignature: StaticRule = {
  id: "a08-unverified-webhook",
  title: "Webhook imza doğrulaması yok",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "high",
  kind: "static",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!isWebhookRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const provider = PROVIDER.test(content) || PROVIDER.test(file);
      if (!provider) continue;
      if (SIGNATURE_VERIFY.test(content)) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "high",
        description:
          "Bir ödeme/entegrasyon webhook uç noktası imza doğrulaması yapmıyor gibi görünüyor. Saldırgan sahte webhook göndererek (ör. ödeme başarılı) veri bütünlüğünü bozabilir.",
        evidence: [fileEvidence(file, 1, file.replace(/\\/g, "/"))],
        remediation:
          "Webhook gövdesini ham (raw) alıp sağlayıcının imza doğrulamasını yapın (Stripe constructEvent, Meta X-Hub-Signature HMAC, svix vb.). Doğrulanmayan isteği reddedin.",
      });
    }
    return findings;
  },
};
