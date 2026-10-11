# Tier 1 — Establish a small, explainable baseline

**Question:** what can a source-code pattern find before the application runs,
and what evidence requires observing a running application?

Work only on this repository's disposable, local fixture and synthetic users.
The unsafe endpoint is deliberately present. Never deploy it, expose it through
a tunnel or proxy, scan another host, or substitute real data or credentials.

## 1. Know what you are measuring

| Check | Evidence it can provide | What it does not establish |
| --- | --- | --- |
| Local Semgrep rule | Direct SQL construction inside Python `execute()` calls | Reachability, untrusted-input provenance, full SQL-injection coverage, tenant authorization |
| Ordinary local HTTP requests | Status, response headers, returned data, route behavior | Exhaustive exploit coverage or a security certification |
| Behavioral regression tests | Assertions for the specified synthetic inputs | Safety of every application path |

SAST and DAST complement each other; neither replaces design review. In this
lab, the fixed, server-owned tenant is a simulation, not authenticated identity.
Binding SQL values and enforcing authorization are separate requirements.

## 2. Run the rule tests, if Semgrep is available

Use an existing Semgrep Community Edition installation. No account, cloud scan,
registry rules, login, paid plan, or API token is needed. Check your installed
version and record it with your results. This repository does not install it.

From the repository root:

```sh
semgrep --version
semgrep --test --metrics off --disable-version-check tier-1-baseline/rules
```

The YAML rule and Python test file intentionally share a filename. Each
`ruleid:` or `ok:` comment labels the following line's expected scanner result.
These are scanner inputs; do not call their functions. All annotations are real
expectations, not ignored TODOs. [Official rule-test documentation](https://docs.semgrep.dev/writing-rules/testing-rules)

## 3. Inspect the fixture with SAST

```sh
semgrep scan --config tier-1-baseline/rules/sql-string-construction.yaml --metrics off --disable-version-check --strict --error app
```

The deliberately concatenated query in `app/lookup.py` should produce a review
candidate. With `--error`, findings return exit code 1; scanner/configuration
errors are different failures and must be investigated. A successful process
without `--error` can still contain findings. Keep the finding visible: do not
suppress or exclude the teaching fixture to manufacture a green result.
[Official CLI behavior](https://docs.semgrep.dev/cli-reference)

This rule checks concatenation, percent formatting, and `.format()` directly in
an `execute()` argument. It deliberately disables constant propagation to keep
the lesson syntactic. It does not verify the receiver's database type, track
values through assignments or helpers, detect all f-string forms, or inspect
authorization. Trusted string fragments can trigger the same rule: the labeled
test includes one such benign candidate to practice triage. Production coverage
needs a maintained ruleset, tuning, and a broader labeled corpus.
[Official rule syntax](https://docs.semgrep.dev/writing-rules/rule-syntax)

Explain why a parameterized query missing the tenant constraint has no match in
these tests, but can still expose another tenant's data. **No match is not a
proof of security.** Do not describe this small search rule as taint analysis.

## 4. Observe the running fixture

Start the app in a separate terminal, from the repository root:

```sh
python -m app.server --port 8080
```

Use ordinary requests against literal loopback only. PowerShell users should
use `curl.exe` rather than the `curl` alias when necessary.

```sh
curl --include --max-time 5 "http://127.0.0.1:8080/health"
curl --include --max-time 5 "http://127.0.0.1:8080/vulnerable/lookup?email=alice%40example.test"
curl --include --max-time 5 "http://127.0.0.1:8080/safe/lookup?email=alice%40example.test"
```

Record status, content type, cache behavior, lab warning, and row count. The
ordinary lookup can work identically on safe and unsafe paths; that observation
does not resolve injection or tenant isolation. These requests are a manual
dynamic baseline, not an OWASP ZAP scan. Move to the bounded negative-case work
in [Tier 2](../tier-2-integrated/README.md) for more meaningful behavioral evidence.
Stop the server with Ctrl+C when finished.

## 5. Keep an evidence record

Write personal results only under the repository's ignored output location.
Record the revision, operating system, Python/Semgrep versions, exact command,
scope, exit code, parsed findings, skipped files, and your triage reasoning.
Do not store request secrets, personal data, or authentication material.

Required learning evidence:

- A passing scanner annotation test run, or an explicit **not run** status.
- The intentional unsafe-code finding, or a recorded rule miss requiring repair.
- A benign candidate explained without hiding it.
- The ordinary HTTP baseline and what it cannot prove.
- An explanation separating bound SQL values from tenant authorization.

## Validation status for the initial authoring environment

Semgrep was not installed in the available runtime. The rule and annotated
corpus were authored against the official syntax, but no Semgrep scan or rule
test was executed; there is no claim of scanner-validated detection. The 12
annotated fixture functions pass Python syntax parsing, with six expected
findings and six expected nonmatches. YAML syntax and the expected rule structure
were checked with an already installed parser; neither check is Semgrep engine
validation. These checks are not a substitute for running `semgrep --test`.
The HTTP commands above are learner instructions, not a claim
that this authoring environment completed live HTTP checks. No scanner was
downloaded, no third-party target was scanned, and no credentials were used.
