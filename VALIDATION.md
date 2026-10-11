# Validation evidence

Initial authoring date: 2026-10-10. Separate demonstrated behavior from tooling that is only supplied as an example.

| Check | Initial authoring result | What it establishes |
| --- | --- | --- |
| Python default test discovery | 27 passed; 4 opt-in live HTTP tests skipped | Selected SQLite behavior, request handling via in-memory transport, and loopback binding constraints. |
| CLI `python -m app.server --help` | Passed | CLI loads; not a browser or scan test. |
| Local TCP integration | Not run successfully; local connection attempts were sandbox-blocked | No claim of authoring-host network validation. |
| Semgrep rule and fixture syntax | YAML/Python syntax and expected rule structure checked | Not a Semgrep-engine result. |
| Semgrep scan / annotated rule test | Not run; scanner not installed | Detection expectations require engine verification. |
| ZAP / Docker scan | Not run | No claim of passive or active scanner coverage. |
| Real authentication, production deployment, branch protection | Not implemented or configured | Fixed tenant context is a simulation, not verified identity. |

The GitHub workflow enables all four self-contained live HTTP integration cases in addition to the 27 offline checks. Inspect [the exact workflow run](https://github.com/KaylahBuilds/sast-dast-tiered-lab/actions/workflows/offline-checks.yml) for the commit you use; a later CI result does not retroactively mean local scanners were run. Its network tests only call the ephemeral service started by the test process on literal `127.0.0.1`.

The initial scanner commands are instructions to validate, not captured successful results. Before using any check as a gate, execute both known-vulnerable and repaired cases, inspect failures and coverage, and record versions and outcomes in the [evidence worksheet](tier-3-risk-driven/evidence-template.md). Do not replace skipped or failed analysis with a success label.
