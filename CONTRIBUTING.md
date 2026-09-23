# Contributing

The one rule: **you cannot improve what you do not measure.**

## Adding a rule

```bash
npm run yeni-kural my-new-rule     # scaffolds rule + BAD/CLEAN tests + registry entry
npm run build && npm test          # the canary will judge you
```

Every rule must ship with BAD and CLEAN fixtures, and declare its
preconditions (`requires`) — an unmet precondition means the rule is reported
as **"not measured"**, never as clean.

## False positives are gold

If the tool flagged something that is safe, open an issue with the
false-positive template. Verified FPs are labelled in the corpus with their
reasoning, and the precision number reflects them.

## The corpus discipline

`corpus/` holds hand-labelled findings (tp/fp). Labels are human verdicts —
LLM-assisted triage exists, but it never writes to the corpus.
