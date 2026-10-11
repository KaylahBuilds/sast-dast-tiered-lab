# SAST vs DAST: a three-tier lab

Understand the difference. Test the control. Keep the evidence.

Companion to [SAST vs DAST: Three Tiers of Security Testing](https://kaylahbuilds.io/#/blog/sast-vs-dast-security-testing-tiers) by Kaylah Builds.

This repository combines a practical adoption guide with a tiny, deliberately vulnerable, **local-only** Python/SQLite application and a repaired implementation. It shows why inspecting source and exercising a running application answer different questions.

**Do not deploy the demo publicly, put it behind a tunnel, or connect it to real data.** Its unsafe endpoint is an intentional teaching fixture, not production code. No credentials or cloud account are needed.

## SAST and DAST at a glance

| Question | SAST: static application security testing | DAST: dynamic application security testing |
| --- | --- | --- |
| What does it inspect? | Source, intermediate representation, or binaries, depending on the analyzer. | A running application through its exposed interfaces. |
| When can it help? | Before deployment, often in the editor or pull request. Some analyzers require a successful build. | Once a testable deployment and usable routes are available. |
| Useful signals | Unsafe data flows and code patterns; a source location to investigate. | Runtime responses, reachable injection behavior, headers and session behavior within tested coverage. |
| Important limits | Models, language/framework support, configuration, and missing business context. A finding is not always exploitable. | Routes, identities, state, and inputs actually reached. A clean unauthenticated scan may have tested only a login page. |
| Operational cost | Build/analysis time, rule tuning, false-positive triage. | Test environments, accounts, scan time, state reset, and possible side effects. |
| Not a replacement for | DAST, dependency/secret scanning, threat modeling, or authorization tests. | SAST, dependency/secret scanning, manual review, or business-logic testing. |

The methods overlap but are not interchangeable. Neither a green job nor an empty report proves an application is secure. SCA (dependency analysis), secret scanning, and infrastructure policy checks complement this work but are distinct controls.

## Three tiers, not three product bundles

These are **this lab's adoption tiers**, not OWASP ASVS levels, compliance categories, analyst seniority levels, or universal vulnerability severities. Higher tiers keep the earlier controls and increase context and evidence. A high-risk service may need Tier 3 immediately.

| Tier | SAST practice | DAST practice | Evidence needed to progress |
| --- | --- | --- | --- |
| [1 — Baseline](tier-1-baseline/README.md) | Narrow, understandable source rules; review findings and fix a small example. | Authorized local exploration and passive response analysis. | Known vulnerable code is detected; a repaired case remains usable; scope and omissions are recorded. |
| [2 — Integrated](tier-2-integrated/README.md) | Repeatable PR checks, pinned tooling, owners, and reviewed gating policy. | Scoped staging checks plus targeted runtime regressions; authenticated coverage when the application supports it. | The correct revision, paths, identities, failures, and remediation are verified—not just job completion. |
| [3 — Risk-driven](tier-3-risk-driven/README.md) | Custom rules and deeper analysis guided by threat models. | Human-led authorization/business-logic testing and targeted active scans. | Abuse cases, role/resource boundaries, approved exceptions, and retests tied to release decisions. |

## Run the dependency-free lab

Requires **Python 3.11 or newer**, including its SQLite module. No pip packages are required for the application or regression suite. Run from the repository root:

```sh
python --version
python -m unittest discover -s tests -v
python -m app.server --port 8080
```

Use `python3` or `py -3` if that is how your installation exposes Python. The server binds only to `127.0.0.1`; do not change that restriction. Stop with Ctrl+C. Each lookup uses a fresh synthetic in-memory database.

The default suite runs 27 database, in-memory HTTP-handler, and binding checks; four live HTTP cases are skipped unless explicitly enabled. To run all 31 where local TCP is permitted, use `RUN_LOCAL_HTTP_TESTS=1 python -m unittest discover -s tests -v` in a POSIX shell, or set `$env:RUN_LOCAL_HTTP_TESTS = '1'` before the test command in PowerShell. The opt-in cases create and stop their own server on an available loopback port; no target URL is accepted. The included CI enables these cases.

Open `http://127.0.0.1:8080/` for the local interface summary. Compare:

- `/vulnerable/lookup?email=...`: deliberately constructed SQL and missing tenant scope.
- `/safe/lookup?email=...`: parameter binding and a server-owned simulated tenant context.
- `/health`: readiness check, not a security assertion.

The tests demonstrate ordinary lookup, SQL injection behavior, and cross-tenant isolation. The safe route is a **repair of these selected behaviors**, not a claim that the HTTP server is production-ready. The tenant context is simulated; there is no login system, OAuth, TLS, role management, or identity-provider integration.

For a real system, derive tenant identity from a verified authorization context. Parameter binding alone does not enforce ownership. Caller-supplied `tenant_id` is not an authorization decision.

## Repository map

```text
app/                    Synthetic HTTP + SQLite demo, vulnerable and safe paths
tests/                  Unit and loopback HTTP regression tests
tier-1-baseline/         Semgrep rule, annotated fixtures, baseline exercise
tier-2-integrated/       Runtime checks, ZAP walkthrough, CI and gating decisions
tier-3-risk-driven/      Threat model, authorization matrix, evidence worksheet
.github/workflows/      Application/regression CI with opt-in loopback tests
SECURITY.md             Safe-use boundaries and reporting guidance
VALIDATION.md           What was actually run and what remains unverified
```

The CI workflow runs the offline application/regression suite. It does **not** run Semgrep, ZAP, active scanning, publish a service, upload scan reports, or enforce branch protection. Configure required checks separately after observing successful and failing sandbox PRs. Do not grant privileged tokens to untrusted pull requests.

## Choose evidence over badge counts

Before promoting a control, keep the tool and rule versions, commit, target, tested identities, seeded failing case, remediation, retest result, owner, and unresolved limitations. Distinguish an analyzer failure from no findings. Treat scan reports as potentially sensitive, even when this particular demo uses synthetic data.

Start with [Tier 1](tier-1-baseline/README.md), then [Tier 2](tier-2-integrated/README.md), and finally [Tier 3](tier-3-risk-driven/README.md). Read [validation status](VALIDATION.md) before treating examples as verified integrations.

## Primary references

- [OWASP source-code analysis](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [OWASP web-security testing guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Semgrep rule tests](https://semgrep.dev/docs/writing-rules/testing-rules)
- [ZAP baseline scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [ZAP authentication guidance](https://www.zaproxy.org/docs/getting-further/authentication/)
- [GitHub secure workflow guidance](https://docs.github.com/en/actions/reference/security/secure-use)
