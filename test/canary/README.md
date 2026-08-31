# canary — a deliberately vulnerable project

This is not a real application. Every file here carries a hole that a rule
family MUST catch, and `test/canary.test.ts` asserts that each one still fires.

Why it exists: tightening a rule reduces false positives, and a falling finding
count looks like progress. It is not — a muted rule lowers the count too. This
project measures the other direction: after a rule is tightened, does it still
see what it was written for?

## Rules for working here

- **Add an example when you tighten a rule.** A fixture is what the author
  imagined; the canary is what the field looks like. The day this project was
  built, a rule whose fixtures all used `req.json()` turned out to no longer see
  form bodies at all.
- **Do not "fix" the holes.** Every one is load-bearing.
- **Some content is deliberately not in English.** Several rules must detect
  non-English identifiers, column names and log messages (a personal-data column
  called `malik`, a status claim written as `bağlı`). An audit tool that only
  understands English makes every codebase written in another language
  invisible. Those fixtures stay as they are on purpose.
- **Watch your sync filters.** This directory contains bait files, including one
  named `.env.local.bak`. An `rsync --exclude .env*` once dropped it silently and
  the recall measurement went wrong without anything failing.

The second canary, `test/canary-sqlite/`, targets SQLite and Python: some rules
cannot be represented in a Next + Supabase project at all.
