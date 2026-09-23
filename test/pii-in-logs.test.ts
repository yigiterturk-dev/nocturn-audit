import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { piiInLogs } from "../src/integrity/pii-in-logs.js";

/**
 * Personal data written to logs.
 *
 * The rule came out of a parallel audit: in one harvesting project the error
 * lines printed a property address, and three distinct street names were measured
 * in the server logs. The risk was low that day (the log sat on the server, it was
 * gitignored) — but the day log collection is added that data goes to a third
 */

const run = (files: Record<string, string>) =>
  piiInLogs.run(makeCtx(files)) as Array<{ severity: string; description: string }>;

describe("int — personal data in logs", () => {
  it("BAD: an address is printed on an error line", () => {
    const f = run({
      "package.json": "{}",
      "lib/zenginlestir.ts": `console.error("zenginleştirme başarısız", propertyAddress, companyName);`,
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("propertyAddress");
  });

  it("BAD + HIGH: with a log collector installed the data already leaves", () => {
    const f = run({
      "package.json": `{"dependencies":{"@sentry/node":"^8"}}`,
      "lib/x.ts": `logger.error("failed", { ownerName, mailingAddress });`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].description).toContain("@sentry/node");
  });

  it("CLEAN: only ids are logged — an id is not personal data", () => {
    // Without this distinction every `console.log({ userId })` would be a finding
    // and the rule would drown in noise.
    const f = run({
      "package.json": "{}",
      "lib/x.ts": `console.log("kayıt işlendi", { residentId, propertyId, tenancyId });`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: an address on a line with no log call is not a finding", () => {
    const f = run({
      "package.json": "{}",
      "lib/x.ts": `const mailingAddress = row.mailing_address;`,
    });
    expect(f.length).toBe(0);
  });

  it("Turkish field names are recognised too", () => {
    const f = run({
      "package.json": "{}",
      "lib/x.ts": `console.warn("bulunamadı", malikAdi, adres);`,
    });
    expect(f.length).toBe(1);
  });
});

describe("int — a log MESSAGE is not a variable (regression)", () => {
  it("CLEAN: a prose log label produces no finding", () => {
    // From real code: `console.log(\`postal address ${pct(...)}\`)` — "postal
    // address" is a human-facing caption whose value is a percentage. The first
    // version counted the template TEXT as identifiers and fired on every line
    // with a prose log message.
    const f = run({
      "package.json": "{}",
      "scraper/x.mjs": "console.log(`  posta adresi    ${pct((r) => r.MAIL_STATE)}`);",
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a plain string message is text too", () => {
    const f = run({
      "package.json": "{}",
      "scraper/y.mjs": `console.log("mahalle ve adres verisi çekiliyor");`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: the INSIDE of an interpolation is still scanned", () => {
    // This is exactly where personal data passes; dropping the interpolation along
    // with the text would have left the rule finding nothing.
    const f = run({
      "package.json": "{}",
      "scraper/z.mjs": "console.error(`kayıt işlenemedi: ${row.mailingAddress}`);",
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("mailingAddress");
  });
});

describe("int — WHOLE-fragment matching (regression)", () => {
  it("CLEAN: MAIL_STATE is a postal STATE, not personal data", () => {
    // From real code: a state code inside a percentage calculation. A substring
    // search fired because it saw "mail".
    const f = run({
      "package.json": "{}",
      "scraper/x.mjs": 'console.log(`eyalet dışı ${pct((r) => r.MAIL_STATE && r.MAIL_STATE !== "NY")}`);',
    });
    expect(f.length).toBe(0);
  });

  it("BAD: ownerMail sahibin posta adresidir", () => {
    const f = run({
      "package.json": "{}",
      "scraper/y.mjs": "console.log(`        posta: ${h.ownerMail}`);",
    });
    expect(f.length).toBe(1);
  });
});

describe("int — 'name' alone is not personal data", () => {
  it("CLEAN: errorName / fileName produce no finding", () => {
    // From real code: `console.error(source, { errorName, errorCode })`. Every
    // codebase has hundreds of `...Name` fields and none of them is a person's
    // name; treating "name" alone as a signal drowned the rule in noise.
    const f = run({
      "package.json": "{}",
      "lib/telemetry.ts": "console.error(input.source, { requestId, fingerprint, errorName, errorCode });",
    });
    expect(f.length).toBe(0);
  });

  it("BAD: ownerName is a person's name", () => {
    const f = run({
      "package.json": "{}",
      "lib/x.ts": "console.error(`bulunamadı: ${row.ownerName}`);",
    });
    expect(f.length).toBe(1);
  });
});

describe("int — a masked value is not a finding", () => {
  it("CLEAN: maskAddress(h.address) is the correct fix", () => {
    // If the rule cannot see this it stays red AFTER the fix and people learn to
    // ignore it. The worst state for a rule is not being wrong, it is looking
    // UNFIXABLE.
    const f = run({
      "package.json": "{}",
      "scraper/x.mjs": "console.log(`${maskeAdres(h.address)}, ${h.town}`);\nconsole.log(`sahip: ${maskeIsim(h.owner)}`);",
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: redact/anonymize/hash wrappers are recognised too", () => {
    const f = run({
      "package.json": "{}",
      "lib/x.ts": "logger.info({ a: redactEmail(user.email), b: hashPhone(user.phone) });",
    });
    expect(f.length).toBe(0);
  });

  it("BAD: a field left OUTSIDE the wrapper is still caught", () => {
    // Half-masking is the sneakiest form: one field hidden, the other exposed.
    const f = run({
      "package.json": "{}",
      "lib/x.ts": "console.log(`${maskeAdres(h.address)} · ${h.ownerName}`);",
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("ownerName");
  });
});

describe("int — LANGUAGE-INDEPENDENT log detection", () => {
  it("BAD: an address inside a Python logging.error", () => {
    // The rule was born from a PYTHON finding but only read JS/TS, so it could not
    // see its own inspiration. A tool that catches a mistake in one language but
    // not another is saying "let us make the same mistake everywhere else".
    const f = run({
      "package.json": "{}",
      "collectors/zenginlestir.py": 'logging.error("zenginleştirme başarısız: %s", mulk_adresi)',
    });
    expect(f.length).toBe(1);
  });

  it("BAD: a field inside a Python f-string is caught", () => {
    const f = run({
      "package.json": "{}",
      "collectors/x.py": 'logging.info(f"kayıt işlenemedi: {row.mailing_address}")',
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: the TEXT of a Python f-string is not a variable", () => {
    const f = run({
      "package.json": "{}",
      "collectors/y.py": 'logging.info(f"posta adresi oranı: {yuzde}")',
    });
    expect(f.length).toBe(0);
  });

  it("BAD: Go and Rust log calls", () => {
    const f = run({
      "package.json": "{}",
      "cmd/main.go": 'fmt.Printf("owner=%s", ownerName)',
      "src/main.rs": 'error!("failed for {}", customer_email);',
    });
    expect(f.length).toBe(2);
  });
});

describe("int — one language's idiom is another's noise", () => {
  it("CLEAN: <p className=...> in JSX is not Ruby's `p` command", () => {
    // With every language merged into one regex, Ruby's `p` print command matched
    // every JSX paragraph and produced 15 false findings in one project. The
    // patterns have to be language-bound.
    const f = run({
      "package.json": "{}",
      "app/x.tsx": '<p className="text-muted">{member.email}</p>',
    });
    expect(f.length).toBe(0);
  });

  it("BAD: puts in a Ruby file is still caught", () => {
    const f = run({
      "package.json": "{}",
      "app/x.rb": 'puts "sahip: #{owner_name}"',
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: Go's fmt.Printf is not looked for in a .ts file", () => {
    const f = run({
      "package.json": "{}",
      "lib/x.ts": 'const s = fmt.Printf("owner=%s", ownerName);',
    });
    expect(f.length).toBe(0);
  });
});

describe("int — a counter is not personal data", () => {
  it("CLEAN: has_surname is a COUNT, not the surname itself", () => {
    // From real code: a log line reporting "number of records that have a
    // surname". A statistic identifies nobody; without the distinction every
    // summary line would be a finding.
    const f = run({
      "package.json": "{}",
      "collectors/x.py": `logging.info(f"  soyadı olan : {o['soyadi_olan']}")`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: adres_sayisi / address_count", () => {
    const f = run({
      "package.json": "{}",
      "lib/x.ts": "console.log(`adres sayısı: ${stats.addressCount}`, stats.adres_sayisi);",
    });
    expect(f.length).toBe(0);
  });

  it("BAD: the surname FIELD ITSELF is still caught", () => {
    const f = run({
      "package.json": "{}",
      "collectors/y.py": `logging.info(f"kayıt: {kisi['soyadi']}")`,
    });
    expect(f.length).toBe(1);
  });
});
