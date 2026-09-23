# CI note

`verify.yml` verifies the tool itself; it does not scan projects.

Why: scanning requires the target projects to exist on disk, and they do not
exist on a CI runner. Running a scan there would report "0 findings", which
means **presenting something unmeasured as clean** — the exact thing this tool
exists to prevent.

The precision gate (`npm run verify`) runs locally, on the machine that holds
the corpus projects.

The workflow you copy into a project you want scanned lives in
`examples/github-workflow.yml`. It is deliberately NOT under
`.github/workflows/`: GitHub runs everything in that directory, so an example
kept there would run against this repository and fail.
