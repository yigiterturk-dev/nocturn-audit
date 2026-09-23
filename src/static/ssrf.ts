import type { Finding } from "../core/finding.js";
import { fileEvidence } from "../core/finding.js";
import type { StaticRule } from "../core/rule.js";

/**
 * A10 — SSRF: a server-side fetch built from user input, with no allowlist.
 */

// A variable URL passed to fetch/axios/got/http.request
const SERVER_REQUEST =
  /\b(fetch|axios|axios\.get|axios\.post|got|http\.request|https\.request|request)\s*\(\s*([`'"]?\$?\{?[A-Za-z_]\w*|`[^`]*\$\{)/;

const INPUT_SOURCE =
  /(req\.|params|searchParams|query\.|body|input|formData|request\.|url\s*=|targetUrl|remoteUrl|imageUrl|webhookUrl|callbackUrl)/i;

// Host validation signals. `.test(host)` and `host.startsWith(...)` were
// missing: one project's SNS certificate check validated the hostname with a
// regex (`/^sns\.[a-z0-9-]+\.amazonaws\.com$/.test(host)`), and the rule did
// not count that as an allowlist, so it reported a finding.
const ALLOWLIST_HINT =
  /(allowlist|allowList|whitelist|isAllowed|isValid\w*Url|ALLOWED_HOSTS|new URL[\s\S]{0,80}(host|hostname)[\s\S]{0,60}(includes|===|==|match|\.test\(|startsWith|endsWith))/i;


/**
 * SSRF REQUIRES the HOST to be under attacker control.
 *
 * Putting user input in a query parameter is not SSRF: adding `?email=...` does
 * not send the request to a different server. Of eight SSRF findings in one run,
 * seven had a FIXED host — `USGS_BASE`, `api.neverbounce.com`,
 * `graph.facebook.com`, `${BASE}/einvoice/...`. An attacker cannot turn those
 * into 169.254.169.254. In the single real finding, the target came from a
 * function parameter: `probe(target)` sent requests to links harvested from the
 * scanned page — there the host genuinely comes from outside.
 *
 * Hence: if scheme and host appear BEFORE the first `${` interpolation, the
 * target is fixed. If it is a variable we step back once to its `const` in the
 * same file; targets that cannot be resolved (parameters, imports) stay findings.
 */
const SEMA_HOST = /^[`'"]\s*https?:\/\/[^`'"$\s]+/;

function sabitTanim(content: string, ad: string): string | null {
  const m = new RegExp(
    `\\b(?:const|let|var)\\s+${ad.replace(/[$]/g, "\\$$")}\\s*=\\s*([^;\n]+)`,
  ).exec(content);
  return m ? m[1].trim() : null;
}

/** Is the HOST part of the target expression fixed? (one level of variable resolution) */
function hostSabitMi(content: string, ifade: string, derinlik = 0): boolean {
  const i = ifade.trim();
  if (!i || derinlik > 2) return false;
  // `process.env.X || "https://..."` → the target is under the OPERATOR's
  // control, not the attacker's. One project's base URL had exactly this shape.
  if (/process\.env\./.test(i) && /https?:\/\//.test(i)) return true;
  // "https://sabit..." ya da `https://sabit${...}` → host sabit
  if (SEMA_HOST.test(i)) return true;
  // `${VARIABLE}...` → resolve the variable
  const interp = /^`\s*\$\{\s*([A-Za-z_$][\w$]*)\s*\}/.exec(i);
  if (interp) {
    const tanim = sabitTanim(content, interp[1]);
    return tanim ? hostSabitMi(content, tanim, derinlik + 1) : false;
  }
  // a bare variable → look at its definition
  const ident = /^([A-Za-z_$][\w$]*)\s*(?:,|\)|$)/.exec(i);
  if (ident) {
    const tanim = sabitTanim(content, ident[1]);
    return tanim ? hostSabitMi(content, tanim, derinlik + 1) : false;
  }
  return false;
}

/** Roughly extract the FIRST argument of the fetch/axios call on this line. */
function ilkArguman(raw: string): string | null {
  const m = /\b(?:fetch|axios(?:\.\w+)?|got|request)\s*\(\s*([\s\S]*)$/.exec(raw);
  if (!m) return null;
  const geri = m[1];
  // Up to the first comma (tracking quotes so a comma inside a template survives)
  let derinlik = 0, tirnak: string | null = null;
  for (let i = 0; i < geri.length; i++) {
    const c = geri[i];
    if (tirnak) {
      if (c === tirnak && geri[i - 1] !== "\\") tirnak = null;
      continue;
    }
    if (c === "`" || c === "'" || c === '"') { tirnak = c; continue; }
    if (c === "(" || c === "{" || c === "[") derinlik++;
    else if (c === ")" || c === "}" || c === "]") { if (derinlik === 0) return geri.slice(0, i); derinlik--; }
    else if (c === "," && derinlik === 0) return geri.slice(0, i);
  }
  return geri;
}


/**
 * An explicit SSRF brake. If a call verifies the target does not reach the
 * internal network, do not report — but recognise it deliberately, not by luck.
 */
const SSRF_FRENI =
  /\b(disHedefMi|isPublicHost|assertPublicUrl|isSafeUrl|validateUrl|guardUrl|blockPrivate|denyPrivate|ssrfGuard|isExternalUrl|checkUrlSafety)\s*\(/i;

/**
 * Is the target a PARAMETER of the enclosing function?
 *
 * `async probe(target: string) { fetch(target) }` — the caller decides the host,
 * so by definition it comes from outside. This is the clearest form of SSRF and
 * must not depend on an accidental clue like "is there a `req.` nearby".
 * Real case: a finding DISAPPEARED after three lines were added, because the ±6
 * line window shifted — the finding went quiet while the hole stayed open.
 */
function parametreMi(lines: string[], i: number, ad: string): boolean {
  for (let j = i; j >= Math.max(0, i - 40); j--) {
    const m = /(?:function\s+\w*|\b(?:async\s+)?(\w+))\s*\(([^)]*)\)\s*(?::[^{]*)?\{/.exec(
      lines[j],
    );
    if (!m) continue;
    const parametreler = (m[2] ?? "").split(",").map((x) => x.trim().split(/[:=\s]/)[0]);
    if (parametreler.includes(ad)) return true;
    // Found the function head but it is not a parameter → do not look further up.
    if (/\bfunction\b|=>/.test(lines[j])) return false;
  }
  return false;
}

const TEMPLATE_YUZEY = /\.(html|hbs|ejs|pug|jinja|j2|vue|svelte)$|(^|\/)templates?\//i;

export const ssrf: StaticRule = {
  id: "a10-ssrf-user-controlled-request",
  title: "Possible SSRF: server request built from user input",
  owasp: "A10:2021-Server-Side Request Forgery",
  severity: "medium",
  kind: "static",
  // No preconditions: relies on reading files.
  /**
   * SSRF bir SUNUCU tarafı zaafıdır: sunucu, saldırganın yönlendirdiği bir
   * adresi kendi ağından çeker. Tarayıcı yüzeyindeki `fetch()` (template,
   * client JS) bunun tersidir — kullanıcının kendi tarayıcısı zaten dışarı
   * çıkar. (gerçek vaka, 2026-09-23: flask celery örneğindeki Jinja template
   * içindeki fetch(event.target.action) SSRF sanıldı — 1 FP.)
   */
  requires: [],
  // Pattern-based detection (that input really reaches an external URL needs manual confirmation).
  confidence: "likely",
  run(ctx): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (TEMPLATE_YUZEY.test(file)) continue;
      if (/(test|spec|fixtures?)/.test(file)) continue;
      const f = file.replace(/\\/g, "/");
      // server side: api/route/actions/lib
      if (!/(app\/|pages\/api\/|route\.|actions?\.|lib\/|server)/.test(f)) continue;
      const content = ctx.read(file);
      if (!content) continue;
      const lines = content.split(/\r?\n/);
      const fileHasAllowlist = ALLOWLIST_HINT.test(content);
      // A client component: the fetch runs IN THE BROWSER. SSRF requires the
      // SERVER to make the request; a request sent from the browser is out of
      // scope by definition. Without this distinction the rule flagged map and
      // dashboard components.
      const istemciBileseni = /^\s*["'`]use client["'`]/m.test(content);
      if (istemciBileseni) continue;

      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!SERVER_REQUEST.test(raw) && !/\bfetch\s*\(\s*\w/.test(raw)) continue;
        const around = lines.slice(Math.max(0, i - 6), i + 3).join("\n");
        const argOn = ilkArguman(raw);
        const adOn = argOn ? /^([A-Za-z_$][\w$]*)\s*(?:,|\)|$)/.exec(argOn.trim()) : null;
        // If the target is a function parameter the host belongs to the caller →
        // no need to look for input clues, this is already the clearest form.
        const targetIsParam = adOn ? parametreMi(lines, i, adOn[1]) : false;
        if (!targetIsParam && !INPUT_SOURCE.test(around)) continue;
        // Skip when an explicit SSRF brake exists (a call that checks the target against the internal network).
        const frenPencere = lines.slice(Math.max(0, i - 12), i + 2).join("\n");
        if (SSRF_FRENI.test(frenPencere)) continue;
        if (fileHasAllowlist) continue;
        // A RELATIVE address: no external host, no SSRF.
        if (/fetch\s*\(\s*[`'"]\//.test(raw)) continue;
        // If the URL comes from an environment variable or configuration, the
        // target is under the OPERATOR's control, not the attacker's. An S3
        // endpoint, a provider base URL, an alert webhook — none of them is SSRF.
        const yapilandirmaKaynakli =
          /process\.env\.|\bconfig\b|\bendpoint\b|\borigin\b|\bbaseUrl\b|\bhedef\b/i.test(around) &&
          !/(req\.|request\.|searchParams|params\.|body\.|formData)/.test(around);
        if (yapilandirmaKaynakli) continue;
        // A FIXED HOST IS NOT SSRF. Putting input in a query parameter does not
        // send the request to another server.
        const arg = ilkArguman(raw);
        if (arg && hostSabitMi(content, arg)) continue;

        // Two levels of confidence:
        //  - Input signals nearby → the target really derives from the request (medium).
        //  - Only "the target is a parameter" → this is an INTERMEDIATE helper
        //    (`fetchText(url)`, `getJson(url)`). The host comes from the caller;
        //    whether it is a hole cannot be known without auditing the CALL SITES.
        //    Calling it medium is noise, ignoring it is blindness → low, with a clear task.
        const sadeceParametre = targetIsParam && !INPUT_SOURCE.test(around);
        findings.push({
          ruleId: this.id,
          title: sadeceParametre
            ? "SSRF carrier: the request target comes from the caller"
            : this.title,
          owasp: this.owasp,
          severity: sadeceParametre ? "low" : "medium",
          description: sadeceParametre
            ? "This helper does not choose the host itself — the caller supplies it. Not a hole on its own, but the carrier for one: if any call site passes user input, requests can be aimed at the internal network. Audit the call sites, or filter the target against private IP ranges here, in one place."
            : "The server makes a request to a URL derived from user input, with no host allowlist or validation in sight. An attacker can make it call internal services (169.254.169.254, localhost, the internal network) — SSRF.",
          evidence: [fileEvidence(file, i + 1, raw)],
          remediation:
            "Validate the target URL against a strict host allowlist, restrict the scheme and host, reject internal IP ranges (metadata, localhost, private), and limit redirects.",
        });
        break;
      }
    }
    return findings;
  },
};
