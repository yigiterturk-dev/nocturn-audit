import { describe, it, expect } from "vitest";
import { makeCtx } from "./helpers.js";
import { piiInRepo } from "../src/integrity/pii-in-repo.js";

/**
 * Personal data inside the repository.
 *
 * This rule came out of a parallel audit: in a deeds/listings harvester, the
 * names and home addresses of 11,634 real people were found committed to git. An
 * irreversible class of mistake, and cheap to detect — reading the header row is enough.
 */

const run = (files: Record<string, string>, overrides?: Parameters<typeof makeCtx>[1]) =>
  piiInRepo.run(makeCtx(files, overrides)) as ReturnType<typeof piiInRepo.run> & Array<{
    severity: string; description: string; confidence?: string;
  }>;

describe("a02 — personal data in the repository", () => {
  it("BAD: name and address columns in a tracked CSV → certain finding", () => {
    const f = run({
      "data/owners.csv": "owner_name,property_address,city\nAhmet Yilmaz,12 Main St,Syracuse\n",
    });
    expect(f.length).toBe(1);
    expect(f[0].confidence).toBe("certain");
    expect(f[0].description).toContain("isim");
    expect(f[0].description).toContain("adres");
  });

  it("BAD: JSONL is covered too", () => {
    const f = run({
      "data/skiptrace.jsonl": `{"full_name":"Jane Doe","phone":"315-555-0100","city":"Syracuse"}\n`,
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: a gitignored file produces no finding", () => {
    // An untracked data file is not a leak; the rule looks only for what has
    // ENTERED GIT.
    const f = run(
      { "data/owners.csv": "owner_name,address\nAhmet,12 Main St\n" },
      { tracked: [] },
    );
    expect(f.length).toBe(0);
  });

  it("CLEAN: one signal is not enough — 'name' can be a product name", () => {
    // Without this distinction every product catalogue would count as personal data.
    const f = run({
      "data/products.csv": "name,sku,price\nMasa,SKU-1,199\n",
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: a template that is nothing but a header is not data", () => {
    const f = run({
      "docs/template.csv": "owner_name,address,phone\n",
    });
    expect(f.length).toBe(0);
  });

  it("CLEAN: stays silent when this is not a git repository", () => {
    // If "is it tracked" cannot be answered, producing a finding with false
    // certainty would be the very mistake this tool chases.
    const f = run(
      { "data/owners.csv": "owner_name,address\nAhmet,12 Main St\n" },
      { isGitRepo: false },
    );
    expect(f.length).toBe(0);
  });

  it("TSV and tab separators are recognised too", () => {
    const f = run({
      "data/list.tsv": "first_name\tmailing_address\tzip\nAli\t5 Elm St\t13206\n",
    });
    expect(f.length).toBe(1);
  });
});

describe("a02 — REAL field headers (regression)", () => {
  it("BAD: compound column names are caught", () => {
    // This header came from a real deeds file. The first version matched the WHOLE
    // column name and missed it — the fixtures passed while the real data slipped
    // through. The same mistake was made twice.
    const f = run({
      "data/onondaga_absentee.csv":
        "municipality_name,print_key_code,parcel_address_number,parcel_address_street," +
        "primary_owner_last_name,mailing_address_street,mailing_address_city,mailing_address_state\n" +
        "Syracuse,1234,12,Main St,Yilmaz,5 Elm St,Rochester,NY\n",
    });
    expect(f.length).toBe(1);
    expect(f[0].description).toContain("isim");
    expect(f[0].description).toContain("adres");
  });

  it("CLEAN: 'ip_address' alone must not be a personal-data signal", () => {
    // A server log is not a personal-data file; the two-family requirement holds this.
    const f = run({
      "data/hits.csv": "ip_address,status,duration_ms\n10.0.0.1,200,12\n",
    });
    expect(f.length).toBe(0);
  });

  it("camelCase headers are split too", () => {
    const f = run({
      "data/leads.csv": "ownerFullName,mailingAddressCity,parcelId\nJane Doe,Syracuse,9\n",
    });
    expect(f.length).toBe(1);
  });
});

describe("a02 — git HISTORY (untracking is not enough)", () => {
  it("BAD: the file was deleted but remains in history → certain finding", async () => {
    const { execFileSync } = await import("node:child_process");
    const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { collectFiles, collectTrackedFiles } = await import("../src/core/engine.js");

    const root = mkdtempSync(join(tmpdir(), "pii-git-"));
    const git = (...args: string[]) =>
      execFileSync("git", args, { cwd: root, stdio: ["ignore", "pipe", "ignore"] });

    git("init", "-q");
    git("config", "user.email", "t@example.invalid");
    git("config", "user.name", "T");

    // 1) Veri commit'leniyor.
    writeFileSync(join(root, "owners.csv"),
      "primary_owner_last_name,mailing_address_street\nYilmaz,5 Elm St\n");
    git("add", "owners.csv");
    git("commit", "-q", "-m", "veri");

    // 2) "Being fixed": untracked and deleted.
    git("rm", "-q", "--cached", "owners.csv");
    writeFileSync(join(root, ".gitignore"), "*.csv\n");
    git("add", ".gitignore");
    git("commit", "-q", "-m", "temizlik");
    rmSync(join(root, "owners.csv"));

    // 3) Today's scan looks clean — but the data is in history.
    const files = await collectFiles(root);
    const tracked = collectTrackedFiles(root);
    const ctx = {
      project: { name: "t", path: root, owned: false, stack: {} },
      root: root,
      files,
      read: () => null,
      readHead: () => null,
      exists: () => false,
      isTracked: (p: string) => Boolean(tracked?.has(p)),
      isGitRepo: true,
      grep: () => [],
    };

    const f = piiInRepo.run(ctx as never) as Array<{ title: string; confidence?: string }>;
    expect(f.length).toBe(1);
    expect(f[0].title).toContain("git HISTORY");
    expect(f[0].confidence).toBe("certain");

    rmSync(root, { recursive: true, force: true });
  });
});

describe("a02 — TURKISH column names (regression)", () => {
  it("BAD: owner + address are caught", () => {
    // In the real repository 9 of 12 data files had Turkish headers and the rule
    // did not see them — the largest a list of 5,172 property owners. An audit
    // tool that does not know its user's language makes every file written in
    // that language invisible.
    const f = run({
      "data/sinyal.csv": "parsel,ilce,adres,malik,posta_onceki,piyasa_degeri\n1,Syracuse,12 Main,Yilmaz,5 Elm,180000\n",
    });
    expect(f.length).toBe(1);
  });

  it("BAD: owner + post (the word address never appears)", () => {
    const f = run({
      "data/portfoy.csv": "malik,posta,eyalet,mulk,toplam_deger\nAli Veli,5 Elm St,NY,3,540000\n",
    });
    expect(f.length).toBe(1);
  });

  it("CLEAN: Turkish data carrying no person produces no finding", () => {
    const f = run({
      "data/ozet.csv": "ilce,toplam_parsel,ort_deger\nSyracuse,1200,180000\n",
    });
    expect(f.length).toBe(0);
  });
});
