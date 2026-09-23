import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A09 — there is a watchdog but no alert target.
 *
 * A monitor without a target reports to itself. Its findings land in a log
 * nobody reads and the whole watch is silent. That is worse than having no
 * monitoring — because monitoring is BELIEVED to exist.
 */
const MONITOR = /(watchdog|monitor|nöbetçi|nobetci|healthcheck|heartbeat)/i;
const ALARM = /(WEBHOOK|SLACK|TELEGRAM|PAGERDUTY|OPSGENIE|SENTRY|DISCORD|ALERT|SMTP|MAIL)/;

export const alertTargetMissing: StaticRule = {
  id: "int-alert-target-missing",
  title: "A monitor runs but has no alert target",
  owasp: "A09:2021-Security Logging & Monitoring Failures",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  requires: [],
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    const ornek = ctx.read(".env.example") || ctx.read(".env.sample") || "";

    for (const file of ctx.files) {
      if (!/\.(ts|js|mjs|sh)$/.test(file) || !MONITOR.test(file)) continue;
      const content = ctx.read(file);
      if (!content) continue;

      // The alert channel may not be read in this file directly: a monitor often
      // imports an alert MODULE. Without looking at imports we were marking every
      // monitor that had wired alerts up properly as "no target".
      const alarmModulu =
        /(import|require)[\s\S]{0,80}?["'`][^"'`]*(alert|alarm|notify|notification|pager|slack|telegram)[^"'`]*["'`]/i.test(content) ||
        /\b(sendAlert|notify|alertsConfigured|dispatchAlert)\s*\(/.test(content);

      const kullanilanAlarm = [...content.matchAll(/process\.env\.(\w*(?:WEBHOOK|ALERT|SLACK|TELEGRAM|PAGERDUTY|SENTRY)\w*)/g)]
        .map((m) => m[1]);
      if (!kullanilanAlarm.length && !alarmModulu) {
        findings.push({
          ruleId: "int-alert-target-missing",
          title: "A monitor runs but has no alert target",
          owasp: "A09:2021-Security Logging & Monitoring Failures",
          severity: "medium",
          confidence: "likely",
          description:
            `\`${file}\` looks like a monitor but reads no alert channel at all. ` +
            "If its findings stay in its own output, nobody ever hears them.",
          evidence: [fileEvidence(file, 1, "no alert channel")],
          remediation: "Configure an alert target (webhook, chat, email) and send every failing check to it.",
        });
        continue;
      }

      if (alarmModulu && !kullanilanAlarm.length) continue;
      const tanimsiz = kullanilanAlarm.filter((ad) => ornek && !ornek.includes(ad));
      if (tanimsiz.length && ALARM.test(tanimsiz[0])) {
        findings.push({
          ruleId: "int-alert-target-missing",
          title: "A monitor runs but has no alert target",
          owasp: "A09:2021-Security Logging & Monitoring Failures",
          severity: "medium",
          confidence: "likely",
          description:
            `\`${file}\` reads these alert variables, but none of them is declared in the example env file: ` +
            `${tanimsiz.join(", ")}. Undefined, the monitor runs silently.`,
          evidence: [fileEvidence(file, 1, tanimsiz.join(", "))],
          remediation: "Add the variables to `.env.example` and confirm they are actually set in production.",
        });
      }
    }
    return findings;
  },
};
