# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories
(**Security → Report a vulnerability**) on this repository. Please do not open
a public issue for an unfixed vulnerability.

Include: what you did, what happened, and what you expected. A minimal
reproduction is worth more than a long description.

Expect an acknowledgement within a few days.

## Scope of this tool

nocturn-audit performs **detection and reporting only**. It does not exploit
findings, does not attempt denial of service, and does not attempt to evade
detection.

Live HTTP probes are non-destructive, low volume, and run **only** against
targets explicitly marked `owned: true` in `targets.json`. Marking a target as
owned is your assertion that you are authorised to test that host. Do not point
this tool at systems you do not have permission to test.

## What the tool reads

Everything runs locally: the CLI reads the paths listed in `targets.json`,
writes reports under `report/`, and makes no network calls other than the live
probes you enable, `npm audit` / `pip-audit`, and the optional LLM triage
(`--ai`, which only runs when `OPENAI_API_KEY` is set and sends the flagged
file to that provider).

Findings can contain secrets and personal data by their nature. Treat
`report/` as sensitive and keep it out of version control.
