import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";
import { collectDogrulamaHelperlari } from "../core/gate-helpers.js";

/**
 * A08 — an unverified webhook.
 * No signature verification on a Stripe/iyzico/Meta/GitHub webhook route.
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
  /(constructEvent|verify\w*Signature|isValidCertUrl|X-Hub-Signature|stripe-signature|Webhook-Signature|createHmac|timingSafeEqual|svix|Webhook\(|x[-_]webhook[-_]secret|webhook[-_]?secret|isWebhookAuthorized|WEBHOOK_SECRET)/i;

export const webhookSignature: StaticRule = {
  id: "a08-unverified-webhook",
  title: "Webhook signature is not verified",
  owasp: "A08:2021-Software & Data Integrity Failures",
  severity: "high",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    // PROJENİN KENDİ doğrulama kapıları (gerçek vaka: isWebhookAuthorized,
    // verifySnsSignature — her proje farklı isimle kapı yazıyor; sabit desen
    // listesi yerine gövde-sinyalli keşif: core/gate-helpers.ts).
    const kapilar = collectDogrulamaHelperlari(ctx);
    for (const file of ctx.files) {
      if (!isWebhookRoute(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const provider = PROVIDER.test(content) || PROVIDER.test(file);
      if (!provider) continue;
      const dosyaKapisi = [...kapilar].some(
        (ad) => new RegExp(`\\b${ad}\\s*\\(`).test(content),
      );
      if (SIGNATURE_VERIFY.test(content) || dosyaKapisi) continue;

      findings.push({
        ruleId: this.id,
        title: this.title,
        owasp: this.owasp,
        severity: "high",
        description:
          "A payment or integration webhook endpoint appears to skip signature verification. An attacker can post forged webhooks (\"payment succeeded\") and corrupt your data.",
        evidence: [fileEvidence(file, 1, file.replace(/\\/g, "/"))],
        remediation:
          "Read the raw webhook body and run the provider's signature verification (Stripe constructEvent, Meta X-Hub-Signature HMAC, svix). Reject anything that fails to verify.",
      });
    }
    return findings;
  },
};
