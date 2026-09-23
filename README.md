# nocturn-audit

A security audit CLI that **measures its own accuracy**.

OWASP Top 10 (2021) mapped. Detection and reporting only — no exploitation,
no DoS, no evasion.

```bash
npx github:yigiterturk-dev/nocturn-audit init   # create targets.json
npx github:yigiterturk-dev/nocturn-audit scan   # scan it
```

## Why another scanner

Most scanners answer one question: *did the pattern match?* This one answers
four, and **measures all four**:

| Question | How it is answered |
|---|---|
| Is what it found real? | A labelled corpus (`nocturn-audit precision`) |
| What does it miss (static)? | A canary — a project left deliberately vulnerable |
| What does it miss (live)? | A live canary — a deliberately vulnerable local server |
| What could it not look at? | A measurement contract — every rule declares its preconditions |
| Was the fix real? | `nocturn-audit diff` — if the file never changed, it is not a fix |

None of these are decoration. Each one exists because the tool got something
wrong:

- Live probes mistook a bot-protection challenge page for the application and
  produced 28 false findings → the measurement contract
- A brake was added to an SSRF hole, the finding vanished, everyone assumed it
  was fixed — the rule's line window had simply shifted → the `diff` command
- While a rule was tightened, `formData` fell out of the taint list and mass
  assignment went invisible; no test caught it → the canary
- An HTTP `timeout=120` was mistaken for a SQLite `busy_timeout` and a real
  finding disappeared silently → the precision gate caught it

## The contract: no findings ≠ clean

A rule returning `[]` is ambiguous — did it look and find nothing, or could it
not look at all? Those are not the same claim, and conflating them is the most
dangerous thing a security tool can do.

So every rule **declares** what it needs (`requires: ["git", "js", …]`). The
engine tests the precondition before running it. Unmet preconditions mean the
rule never runs, and the report says **"not measured"** with the reason —
instead of quietly reading as clean.

```
⃠ not measured (5 rule(s)): not a git repository — a02-pii-in-repo, a02-secrets-git-history, …
```

## Install

Run it straight from this repository — nothing to install:

```bash
npx github:yigiterturk-dev/nocturn-audit init
```

Pin a version with a tag, which is what you want in CI:

```bash
npx github:yigiterturk-dev/nocturn-audit#v0.1.0 scan --static
```

Or clone and link it:

```bash
git clone https://github.com/yigiterturk-dev/nocturn-audit
cd nocturn-audit && npm install && npm link
nocturn-audit --help
```

Requires Node 20+. (The `invariants` command additionally needs Node 22.5+,
where the built-in `node:sqlite` module exists; everything else runs on 20.)

## targets.json

`init` writes one for the current project. It is a list of what to scan:

```json
{
  "projects": [
    {
      "name": "my-web-app",
      "path": "~/code/my-web-app",
      "url": "https://my-web-app.example.com",
      "owned": true,
      "stack": { "framework": "next", "db": "supabase", "auth": "clerk" }
    }
  ]
}
```

**`owned` gates the live probes.** They run only against targets marked
`owned: true`. Leave it `false` unless you are authorised to test that host.
Leave `stack` out and it is detected from `package.json` / `pyproject.toml`.

## Usage

```bash
nocturn-audit scan                  # everything in targets.json
nocturn-audit scan my-web-app       # one project
nocturn-audit scan --static         # static only, never touch the live host
nocturn-audit rules                 # the active rule set
nocturn-audit standards             # the security + performance checklist
nocturn-audit diff report/2026-08-30.json report/2026-08-31.json
```

`scan` exits `1` when a critical finding is present, so it works as a CI gate.
A ready-made GitHub Actions workflow is in
[`examples/github-workflow.yml`](examples/github-workflow.yml).

### `diff` — "the finding vanished" is not "the hole is closed"

A finding can disappear because you fixed it, or because you changed the rule.
`diff` compares two reports and checks whether the file behind each vanished
finding actually changed. If it did not, the disappearance is reported as
suspicious and the command exits `1` — so nobody celebrates a smaller number.

### Confidence: certain vs likely

Every finding carries a confidence. `certain` findings are deterministic —
a committed `.env`, a provider key literal, an expired certificate. `likely`
findings are heuristic and want a human. The summary counts them separately,
because a scanner that mixes them trains you to ignore it.

## The Shannon core: one maths for every randomness claim

`src/core/shannon.ts` is the tool's measurement brain. Every rule that asks
"how random is this string, really?" measures through one module instead of a
private copy:

| Measure | Answers |
|---|---|
| `shannonEntropy` | H in bits/char — how surprised are we by the next character |
| `normalizedEntropy` | random **for its own alphabet** — a hex string can never exceed 4 bits/char |
| `keyspaceBits` | the brute-force budget of the whole string (64/112-bit bands) |
| `maxRun` / `dgaLikeness` | structure entropy cannot see: `aaaa…`, algorithmically generated hosts |

Powered by it: the hardened hardcoded-secret rule (its findings now carry
measured numbers), and `a07-weak-random-token` — tokens derived from
`Math.random()` / `Date.now()`, and CSPRNG draws whose **measured keyspace** is
below the token floor (`randomBytes(8)` = 64 bits = marginal, whatever the
source).

## The pislik score: comparable dirtiness

`score` is an unbounded weighted sum. The **pislik score** (0-100) normalises
it — `min(100, raw × 2)` — so projects of different sizes are comparable:
*tertemiz / tozlu / kirli / pis / çok pis / biyolojik tehlike*.

One honesty rule, same as everything else here: when a rule could not run, the
score is a **lower bound** and the report says `(kısmi ölçüm)` — a 0 with gaps
is not "clean", it is "the measured part is clean".

## LLM triage — Jev first

`--ai` triages high/critical findings with an LLM. The provider is chosen by
environment: **Jev** (`JEV_AI_API_KEY`, same contract as legafetch's
`jev_mevzuat.py` — `{model, state, questions}` → typed answers) with OpenAI as
the fallback (`OPENAI_API_KEY`).

House doctrine, mirrored from legafetch: **Jev does not do arithmetic** — it
receives only finding text and evidence; the 0.5 threshold lives in code. If
Jev is unreachable, triage is skipped and the scan is unaffected. Triage never
touches the precision corpus; to pre-triage **unlabelled corpus findings** run

```bash
JEV_AI_API_KEY=... npm run jev-triyaj            # writes corpus/jev-oneri-<date>.md (+json)
```

It produces a review sheet of AI-suggested verdicts. You label `labels.json`
by hand — the corpus stays human-verified by design.

## Coverage

OWASP Top 10 (2021), plus two families of rules that came out of running real
audits:

- **Dependency rules** — `npm audit` and `pip-audit`, with a production vs.
  dev-tree split (a vulnerable build tool is not a live risk)
- **Integrity rules (`int-*`)** — for a class of failure security rules miss.
  Security rules ask *can someone get in?*; these ask *is the system telling
  the truth about itself?* Hardcoded status values, monitors with no alert
  target, backups never restore-rehearsed, test lists enumerated by hand,
  immutability guards that block UPDATE but not DELETE.

`nocturn-audit rules` prints the full set with OWASP category and CWE.

### It reads more than English

Several rules match non-English identifiers, column names and log messages as
well as their English equivalents — a personal-data column named in Turkish, a
status claim written as `bağlı` rather than `connected`. This came out of a real
audit: an early version knew only English headers and missed 9 of 12 data files
in a repository, the largest a list of 5,172 people. A tool that only
understands English makes every codebase written in another language invisible.

## Writing a rule

```bash
nocturn-audit new-rule a01-my-rule
```

This scaffolds the rule, its tests and the registry entry — and **the generated
tests start red**. A rule does not go green until three things exist:

1. a **BAD** fixture: a realistic example it must catch
2. a **CLEAN** fixture: something that looks like it but must not be caught —
   this is the hard one, false positives are born here
3. a `requires` declaration (an empty array is a valid one)

The registry entry is written for you, because forgetting it means the rule
silently never runs, and a silent rule is worse than a missing one.

Prefer `ctx.ast(file)` over text search whenever the question is structural
(*what does this call target, where does this value come from*). Most false
positives in this tool came from structural questions asked with a regex.

## Reports

Every scan writes `report/YYYY-MM-DD.html` (readable) and
`report/YYYY-MM-DD.json` (machine-readable, and the input to `diff`).

## Scope and limits

Detection and reporting. This tool does not exploit, does not attack, and does
not attempt evasion. Live probes are non-destructive, low volume, and run only
against hosts you declare as your own.

## Licence

MIT © Yiğit Ertürk

---

Türkçe belgeler: [README.tr.md](README.tr.md)
