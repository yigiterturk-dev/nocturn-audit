import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { hardcodedStatus } from "../src/integrity/hardcoded-status.js";
import { handEnumeratedTestList } from "../src/integrity/hand-enumerated-test-list.js";
import { generatedFileHandEdited } from "../src/integrity/generated-file-hand-edited.js";
import { scopeHandEnumerated } from "../src/integrity/scope-hand-enumerated.js";
import { permissionAfterValidation } from "../src/integrity/permission-after-validation.js";
import { updateGuardWithoutDelete } from "../src/integrity/update-guard-without-delete.js";
import { sessionRevokeMissing } from "../src/integrity/session-revoke-missing.js";
import { backupWithoutRestoreRehearsal } from "../src/integrity/backup-without-restore-rehearsal.js";
import { alertTargetMissing } from "../src/integrity/alert-target-missing.js";
import { staticPageStrictCsp } from "../src/integrity/static-page-strict-csp.js";
import { contractTwoWriters } from "../src/integrity/contract-two-writers.js";
import { scanAfterWrite } from "../src/integrity/scan-after-write.js";
import { ssrf } from "../src/static/ssrf.js";

/**
 * Every rule has a BAD and a CLEAN fixture.
 *
 * Why this file exists: a rule that never fires is not a rule. A check that stays
 * silent about what it cannot measure does not say "clean", it says nothing — and
 * the more rules there are, the bigger that illusion grows. No rule without a BAD
 * bu depoya girmemeli.
 */

const run = <T extends { run: (ctx: ReturnType<typeof makeCtx>) => unknown }>(
  rule: T,
  files: Record<string, string>,
) => rule.run(makeCtx(files)) as Array<{ severity: string; description: string }>;

describe("int — status is hardcoded", () => {
  it("BAD: health servisi 'ready: true' sabitliyor", () => {
    const f = run(hardcodedStatus, {
      "lib/system/health.ts": `export function status() { return { serviceReady: true, database: check() }; }`,
    });
    expect(f.length).toBeGreaterThan(0);
  });

  it("CLEAN: the status comes from a real measurement", () => {
    const f = run(hardcodedStatus, {
      "lib/system/health.ts": `export async function status() { return { serviceReady: await pingDb() }; }`,
    });
    expect(f.length).toBe(0);
  });

  // This rule once produced 22 findings across 5 projects, all false. It looked at
  // the line, not at the branch.
  it("CLEAN: 'ok' AFTER the query ran, 'unavailable' in the catch", () => {
    const f = run(hardcodedStatus, {
      "app/api/health/route.ts": `export async function GET(request) {
  try {
    await getDb().execute(sql\`select 1 as ready\`);
    return Response.json({ status: "ok", checks: { database: "ok" } });
  } catch (error) {
    return Response.json({ status: "unavailable" }, { status: 503 });
  }
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: the answer of an `if (!stateDir)` branch looks constant but is a measurement", () => {
    const f = run(hardcodedStatus, {
      "src/lib/etl-monitor.ts": `export async function etlStatus(options) {
  const stateDir = options?.stateDir ?? process.env.ETL_STATE_DIR?.trim() ?? "";
  const qdrant = await qdrantStatus(fetchFn);
  if (!stateDir) {
    return {
      configured: false,
      state: "not-started",
    };
  }
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: Prisma `select: { status: true }` is a field selection, not a status claim", () => {
    const f = run(hardcodedStatus, {
      "src/app/api/public-data/status/route.ts": `export async function GET() {
  const son = await prisma.run.findFirst({
    select: { status: true, startedAt: true, finishedAt: true },
  });
  return Response.json(son);
}`,
    });
    expect(f.length).toBe(0);
  });

  // Verified during the move to the tree (the two remaining false findings from one run):
  it("CLEAN: still a branch answer even when the measurement is 30 lines above", () => {
    const dolgu = Array.from({ length: 30 }, (_, i) => `  const ara${i} = ${i};`).join("\n");
    const f = run(hardcodedStatus, {
      "src/lib/etl-monitor.ts": `export async function durum(options) {
  const progressRaw = await readJson(yol);
${dolgu}
  return {
    configured: true,
    state: "running",
  };
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a named module constant is a template, not a claim", () => {
    const f = run(hardcodedStatus, {
      "src/lib/real-estate-monitor.ts": `const unavailable: Status = {
  available: false,
  health: { status: "unavailable", checkedAt: null },
};
export default unavailable;`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: if the opposite value is returned in the same function it is a branch outcome", () => {
    const f = run(hardcodedStatus, {
      "server_lib/seoHealth.ts": `export function ozetle(m, url, strategy) {
  if (!m) {
    return { available: false, reason: "veri yok" };
  }
  return { available: true, url, strategy };
}`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: a hardcoded field NEXT TO a measured one is the sneakiest → finding", () => {
    // Half the screen real, half invented. No opposite value, no branch.
    const f = run(hardcodedStatus, {
      "lib/system/health.ts": `export function status() { return { serviceReady: true, database: check() }; }`,
    });
    expect(f.length).toBeGreaterThan(0);
  });

  it("BAD: a health endpoint returning 'ok' with no measurement is still a finding", () => {
    const f = run(hardcodedStatus, {
      "app/api/health/route.ts": `export function GET() {
  return Response.json({ status: "ok", checks: { database: "ok" } });
}`,
    });
    expect(f.length).toBeGreaterThan(0);
  });
});

describe("int — the test list is enumerated by hand", () => {
  it("BAD: a test file exists that is not on the list → high", () => {
    const f = run(handEnumeratedTestList, {
      "package.json": JSON.stringify({
        scripts: { test: "node --test tests/a.test.mjs tests/b.test.mjs tests/c.test.mjs" },
      }),
      "tests/a.test.mjs": "", "tests/b.test.mjs": "", "tests/c.test.mjs": "",
      "tests/unutulan.test.mjs": "",
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].description).toContain("unutulan.test.mjs");
  });

  it("CLEAN: a glob is used, nothing is enumerated by hand", () => {
    const f = run(handEnumeratedTestList, {
      "package.json": JSON.stringify({ scripts: { test: "vitest run" } }),
      "tests/a.test.mjs": "",
    });
    expect(f.length).toBe(0);
  });
});

describe("int — hand edits in a generated file", () => {
  it("BAD: a generated file whose generator has no 'additions' hook", () => {
    const f = run(generatedFileHandEdited, {
      "db/schema.sql": "-- GENERATED FILE — do not edit.\nCREATE TABLE a();",
      "scripts/generate.mjs": `writeFileSync("db/schema.sql", sql); // generate`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });

  it("CLEAN: the generator appends a separate additions file", () => {
    const f = run(generatedFileHandEdited, {
      "db/schema.sql": "-- GENERATED FILE — do not edit.\nCREATE TABLE a();",
      "scripts/generate.mjs": `const extra = readFileSync("db/schema-additions.sql"); writeFileSync("db/schema.sql", sql + extra); // generate`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — the scoper enumerates by hand", () => {
  const anahtarlar = ["a","b","c","d","e","f","g","h","i","j"]
    .map((k) => `    ${k}: take(snapshot.${k}),`).join("\n");

  it("BAD: ...snapshot is spread and 10 keys are filtered by hand", () => {
    const f = run(scopeHandEnumerated, {
      "lib/scope.ts": `export function scopeSnapshot(snapshot, actor) {\n  return {\n    ...snapshot,\n${anahtarlar}\n  };\n}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });

  it("CLEAN: the keys are derived from a list", () => {
    const f = run(scopeHandEnumerated, {
      "lib/scope.ts": `export function scopeSnapshot(snapshot, actor) {\n  return Object.fromEntries(Object.entries(snapshot).map(([k, v]) => [k, take(v)]));\n}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — authorisation check after validation", () => {
  it("BAD: safeParse first, canManage second", () => {
    const f = run(permissionAfterValidation, {
      "app/api/x/route.ts": `export async function POST(req) {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) return bad();
  if (!canManage(actor.role, parsed.data.resource)) return forbidden();
}`,
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: the authorisation check comes first", () => {
    const f = run(permissionAfterValidation, {
      "app/api/x/route.ts": `export async function POST(req) {
  if (!canManage(actor.role, raw.resource)) return forbidden();
  const parsed = schema.safeParse(raw);
}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — UPDATE guarded, DELETE open", () => {
  it("BAD: sadece UPDATE tetikleyicisi var", () => {
    const f = run(updateGuardWithoutDelete, {
      "db/schema.sql": `CREATE OR REPLACE TRIGGER t1_no_update BEFORE UPDATE ON ledger_entries FOR EACH ROW EXECUTE FUNCTION fn();`,
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("ledger_entries");
  });

  it("CLEAN: ikisi de var", () => {
    const f = run(updateGuardWithoutDelete, {
      "db/schema.sql": `CREATE OR REPLACE TRIGGER t1 BEFORE UPDATE ON ledger_entries FOR EACH ROW EXECUTE FUNCTION fn();
CREATE OR REPLACE TRIGGER t2 BEFORE DELETE ON ledger_entries FOR EACH ROW EXECUTE FUNCTION fn2();`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — access revoked, session not closed", () => {
  it("BAD: changePassword does not invalidate the session", () => {
    const f = run(sessionRevokeMissing, {
      "lib/auth.ts": `const s = "session";
export async function changePassword(input) {
  await db.update(users).set({ hash: await hash(input.next) });
  return { ok: true };
}`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });

  it("CLEAN: çerezi silen fonksiyon oturumu zaten kapatır (yanlış alarm değil)", () => {
    const f = run(sessionRevokeMissing, {
      "lib/auth/mode.ts": `import { cookies } from "next/headers";
const DEMO_COOKIE = "demo";
export async function disableDemoMode() {
  const store = await cookies();
  store.delete(DEMO_COOKIE);
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: session_epoch ileri alınırsa açık oturumlar düşer", () => {
    const f = run(sessionRevokeMissing, {
      "lib/auth/admin.ts": `const s = "session";
export async function deactivateUser(id) {
  await db.update(users).set({ session_epoch: new Date() }).where(eq(users.id, id));
}`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: old sessions are closed", () => {
    const f = run(sessionRevokeMissing, {
      "lib/auth.ts": `const s = "session";
export async function changePassword(input) {
  await db.update(users).set({ hash: await hash(input.next) });
  await revokeSessionsForEmail(input.email, "actor", "sifre degisti");
}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — no restore rehearsal", () => {
  it("BAD: there is a pg_dump but no restore", () => {
    const f = run(backupWithoutRestoreRehearsal, {
      "scripts/backup.mjs": `await run("pg_dump", ["-d", url, "-f", target]); await upload(target);`,
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: it restores the dump into a separate database", () => {
    const f = run(backupWithoutRestoreRehearsal, {
      "scripts/backup.mjs": `await run("pg_dump", ["-f", target]); await run("psql", ["-d", probeUrl, "-f", target]);`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — there is a watchdog but no alert target", () => {
  it("BAD: the watchdog reads no alert channel", () => {
    const f = run(alertTargetMissing, {
      "scripts/watchdog.mjs": `const r = await fetch("/api/health/live"); if (!r.ok) console.log("DUSTU");`,
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: a webhook is read and declared in the example env", () => {
    const f = run(alertTargetMissing, {
      ".env.example": "ALERT_WEBHOOK=\n",
      "scripts/watchdog.mjs": `const hedef = process.env.ALERT_WEBHOOK; await fetch(hedef, { method: "POST" });`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — a static page under strict-dynamic", () => {
  const csp = { "proxy.ts": `const csp = "script-src 'self' 'strict-dynamic'";` };

  it("BAD: the page is not bound to request time", () => {
    const f = run(staticPageStrictCsp, {
      ...csp,
      "app/not-found.tsx": `export default function NotFound() { return <div>yok</div>; }`,
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: bound with connection()", () => {
    const f = run(staticPageStrictCsp, {
      ...csp,
      "app/not-found.tsx": `export default async function NotFound() { await connection(); return <div>yok</div>; }`,
    });
    expect(f.length).toBe(0);
  });

  it("COMMENT TRAP: a finding IS produced when connection() appears only in a comment", () => {
    // This assertion comes from a mistake we made ourselves: text search caught the
    // word in the comment and let the rule pass silently.
    const f = run(staticPageStrictCsp, {
      ...csp,
      "app/not-found.tsx": `/** A connection() call binds the page to the request. */
export default function NotFound() { return <div>yok</div>; }`,
    });
    expect(f.length).toBe(1);
  });

  it("SCOPE: with no strict-dynamic in the project the rule never runs", () => {
    const f = run(staticPageStrictCsp, {
      "app/not-found.tsx": `export default function NotFound() { return <div>yok</div>; }`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: 'use client' error boundaries are not flagged (they are never statically generated)", () => {
    // error/global-error CANNOT use connection()/force-dynamic (they are client
    // components) and Next never statically generates them — they cannot be expected to bind to the request.
    const f = run(staticPageStrictCsp, {
      ...csp,
      "app/error.tsx": `"use client";\nexport default function Error() { return <a href="/">yeniden</a>; }`,
      "app/global-error.tsx": `"use client";\nexport default function GlobalError() { return <a href="/">yeniden</a>; }`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: an error boundary WITHOUT 'use client' is flagged (it may be statically generated with no nonce)", () => {
    const f = run(staticPageStrictCsp, {
      ...csp,
      "app/error.tsx": `export default function Error() { return <div>error</div>; }`,
    });
    expect(f.length).toBe(1);
  });
});

describe("int — two places write the contract", () => {
  it("BAD: one .ts and one .mjs writing the same fields", () => {
    // In its first form this fixture shared no field names at all. As such there
    // was no evidence they were "the same contract" — two unrelated JSON writers
    // would look identical, and the rule must not flag those.
    const f = run(contractTwoWriters, {
      "lib/meta.ts": `writeFileSync(metadataPath(fileName), JSON.stringify({ fileName, checksum, sizeBytes }));`,
      "scripts/backup.mjs": `await writeFile(target + ".json", JSON.stringify({ fileName, checksum }));`,
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: two unrelated JSON writers → NO finding", () => {
    // The distinction itself: two writers in the same language is not enough, there
    // must be a signal that they write the SAME contract.
    const f = run(contractTwoWriters, {
      "lib/cache.ts": `writeFileSync("cache.json", JSON.stringify({ entries, evictedAt }));`,
      "scripts/sitemap.mjs": `await writeFile("sitemap.json", JSON.stringify({ routes, lastmod }));`,
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a single writer", () => {
    const f = run(contractTwoWriters, {
      "lib/meta.ts": `writeFileSync(path + ".json", JSON.stringify(summary));`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — scanning after the write", () => {
  it("BAD: put first, then scan", () => {
    const f = run(scanAfterWrite, {
      "lib/upload.ts": `await driver.put(key, bytes); const v = await scanDocument(bytes); if (!v.clean) await driver.remove(key);`,
    });
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("high");
  });

  it("CLEAN: scan first, then put", () => {
    const f = run(scanAfterWrite, {
      "lib/upload.ts": `const v = await scanDocument(bytes); if (!v.clean) throw new Error("kirli"); await driver.put(key, bytes);`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — does the contract rule catch the real case (regression)", () => {
  it("BAD: the path comes from a helper and the body has JSON.stringify", () => {
    // This assertion comes from the case where the rule FAILED on a real project.
    // The first version looked only for the text `.json` inside the call; in the
    // real code the path came from a `metadataPath(...)` helper, so it never
    // matched and the rule missed the very reason it was written.
    const f = run(contractTwoWriters, {
      "lib/system/service.ts": `await writeFile(metadataPath(summary.fileName), JSON.stringify(summary, null, 2));`,
      "scripts/backup.mjs": `await writeFile(\`\${target}.json\`, JSON.stringify({ fileName, checksum }, null, 2));`,
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("scripts/backup.mjs");
  });
});

describe("int — a liveness endpoint is legitimately constant", () => {
  it("CLEAN: /api/health/live may return a constant 'ok'", () => {
    const f = run(hardcodedStatus, {
      "app/api/health/live/route.ts": `export function GET() { return json({ status: "ok" }); }`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: a readiness endpoint hardcoding it DOES produce a finding", () => {
    const f = run(hardcodedStatus, {
      "app/api/health/ready/route.ts": `export function GET() { return json({ serviceReady: true }); }`,
    });
    expect(f.length).toBe(1);
  });
});

describe("int — constants that are the RESULT of a measurement are not findings", () => {
  it("CLEAN: an `as const` branch label is not flagged", () => {
    // `return { configured: false as const }` is a TypeScript idiom: it labels the
    // branch of a discriminated union, and a real check happened above it.
    // Not a constant claim but the answer of a measurement.
    const f = run(hardcodedStatus, {
      "lib/system/offsite.ts": `export async function age() {
  if (!configuredCheck()) return { configured: false as const, ageHours: null };
  return { configured: true as const, ageHours: hesapla() };
}`,
    });
    expect(f.length).toBe(0);
  });
});

describe("int — the alert channel may come from a module", () => {
  it("CLEAN: the monitor imports the alert module", () => {
    // Monitors usually send alerts by calling an alert module rather than reading
    // env directly. A rule that ignored imports flagged every monitor that had
    // wired alerts up properly as having 'no target'.
    const f = run(alertTargetMissing, {
      "scripts/watchdog.mjs": `const { sendAlert, alertsConfigured } = await import("../lib/system/alerts.ts");
if (!alertsConfigured()) process.stderr.write("alarm hedefi yok\\n");
else await sendAlert({ bulgular });`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: no alert channel at all", () => {
    const f = run(alertTargetMissing, {
      "scripts/watchdog.mjs": `const r = await fetch("/health"); if (!r.ok) console.log("DUSTU");`,
    });
    expect(f.length).toBe(1);
  });
});

describe("a10 — the SSRF distinction", () => {
  // These three assertions encode the three separate causes of four false
  // positives in one scan. None of them let an attacker choose the target.
  it("CLEAN: a relative address — no external host", async () => {
    const f = await ssrf.run(makeCtx({
      "lib/x.ts": `const sp = new URLSearchParams(req.query); await fetch(\`/api/points?\${sp}\`);`,
    }));
    expect(f.length).toBe(0);
  });

  it("CLEAN: the target comes from an environment variable — under the operator's control", async () => {
    const f = await ssrf.run(makeCtx({
      "lib/alerts.ts": `const hedef = process.env.ALERT_WEBHOOK; const body = JSON.stringify(input);
await fetch(hedef, { method: "POST", body });`,
    }));
    expect(f.length).toBe(0);
  });

  it("BAD: hedef istekten geliyor, allowlist yok", async () => {
    const f = await ssrf.run(makeCtx({
      "app/api/proxy/route.ts": `export async function POST(req) {
  const body = await req.json();
  const response = await fetch(body.targetUrl);
  return response;
}`,
    }));
    expect(f.length).toBe(1);
  });
});

describe("int — an updated_at trigger is not a guard", () => {
  it("CLEAN: a `before update` timestamp trigger produces no finding", () => {
    // This is the most common trigger in Postgres and it forbids nothing. Without
    // the distinction the rule produced a "deletes are open" finding for every
    // project using `updated_at` — it was the only HIGH in one scan.
    const f = run(updateGuardWithoutDelete, {
      "db/003.sql": `create function set_updated_at() returns trigger as $$
begin new.updated_at = now(); return new; end;
$$ language plpgsql;
create trigger deals_updated_at before update on deals
  for each row execute function set_updated_at();`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: there is a REJECTING update trigger and no delete counterpart", () => {
    const f = run(updateGuardWithoutDelete, {
      "db/004.sql": `create function fn_ledger_no_update() returns trigger as $$
begin RAISE EXCEPTION 'ledger entry is immutable'; end;
$$ language plpgsql;
create trigger t1_ledger_no_update before update on ledger_entries
  for each row execute function fn_ledger_no_update();`,
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("ledger_entries");
  });
});

describe("int — the trigger BODY is read (regression)", () => {
  it("CLEAN: a delete guard with no keyword in its name but a RAISE in its body is recognised", () => {
    // In the real schema the guard was named `t094_application_applicant_delete` —
    // it carried no word like "immutable" or "no_delete", and the rejection lived
    // IN THE BODY. Because the rule matched the body lazily up to `AS $$` it
    // stopped at the OPENING `$$` and never read the body; every guard that did
    // RAISE was counted as "not rejecting".
    const f = run(updateGuardWithoutDelete, {
      "db/x.sql": `CREATE OR REPLACE FUNCTION fn_a_update() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'row is immutable'; END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER a_update BEFORE UPDATE ON kayitlar FOR EACH ROW EXECUTE FUNCTION fn_a_update();
CREATE OR REPLACE FUNCTION fn_a_delete() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'row cannot be deleted'; END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER a_delete BEFORE DELETE ON kayitlar FOR EACH ROW EXECUTE FUNCTION fn_a_delete();`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: update RAISEs and there is NO delete trigger at all", () => {
    const f = run(updateGuardWithoutDelete, {
      "db/y.sql": `CREATE OR REPLACE FUNCTION fn_b_update() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'row is immutable'; END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE TRIGGER b_update BEFORE UPDATE ON kayitlar FOR EACH ROW EXECUTE FUNCTION fn_b_update();`,
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("kayitlar");
  });
});

describe("int — scan-after-write (Express route FP)", () => {
  it("app.put('/route', ...) + baska yerde scan → bulgu YOK (route, yazma degil)", () => {
    const f = scanAfterWrite.run(makeCtx({
      "server.ts": `app.put('/api/radar/:id/competitors', requireAuth(), async (req, res) => { res.json(await save(req.body)); });
async function scanDocument(b){ return { clean: true }; }`,
    })) as Array<unknown>;
    expect(f.length).toBe(0);
  });
});

describe("int — scan-after-write (the bare scan FP)", () => {
  it("writeFile plus a project-scanning scan() (not malware) → NO finding", () => {
    const f = scanAfterWrite.run(makeCtx({
      // A real case: an atomic JSON write plus the tool's own scanProject
      "electron/store.ts": `function writeJson(file, v){ writeFileSync(file, JSON.stringify(v)); }
async function scanProject(p){ return runRules(p); }`,
    })) as Array<unknown>;
    expect(f.length).toBe(0);
  });
});

import { backupWithoutRestoreRehearsal } from "../src/integrity/backup-without-restore-rehearsal.js";

const runYedek = (files: Record<string, string>) =>
  backupWithoutRestoreRehearsal.run(makeCtx(files)) as Array<{ severity: string }>;

/**
 * The rule reported a `scripts/dump-schema.mjs` as "backup taken but no
 * rehearsal". That script prints the schema TO THE SCREEN — an inspection tool,
 * not a backup system. Asking about the restorability of a dump whose output is
 * stored nowhere is meaningless.
 */
describe("int — the backup rehearsal: a backup is something WRITTEN somewhere", () => {
  it("CLEAN: an inspection script printing the schema to the screen is not a backup", () => {
    const f = runYedek({
      "scripts/dump-schema.mjs": `const { data: tables } = await supabase.from("information_schema.tables").select();
for (const t of tables) {
  console.log("-- Table: " + t.table_name);
}`,
    });
    expect(f.length).toBe(0);
  });

  it("BAD: a dump written to a file with no restore rehearsal → finding", () => {
    const f = runYedek({
      "scripts/backup.mjs": `import { writeFileSync } from "node:fs";
const dump = await pg_dump();
writeFileSync("/yedek/db.sql", dump);`,
    });
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("CLEAN: it writes to a file BUT it also rehearses the restore", () => {
    const f = runYedek({
      "scripts/backup.mjs": `import { writeFileSync } from "node:fs";
const dump = await pg_dump();
writeFileSync("/yedek/db.sql", dump);
await pg_restore("/yedek/db.sql", { hedef: "dogrulama_db" });`,
    });
    expect(f.length).toBe(0);
  });
});
