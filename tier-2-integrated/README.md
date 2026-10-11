# Tier 2 — integrate checks without inventing confidence

Keep Tier 1's source review and introduce repeatable runtime evidence. The default suite exercises SQLite and the HTTP handler through an in-memory transport. Four opt-in integration tests exercise an ephemeral loopback service; CI enables them. These are **targeted dynamic regression tests**, not a general-purpose DAST scanner or proof of authenticated coverage.

## Exercise 1: compare source and runtime evidence

```sh
python -m unittest discover -s tests -v
```

To include real TCP integration in a permitted local environment, use `RUN_LOCAL_HTTP_TESTS=1 python -m unittest discover -s tests -v` in a POSIX shell. In PowerShell, set `$env:RUN_LOCAL_HTTP_TESTS = '1'` before running the test command. The default four skips are explicit—not successful live checks.

Review the assertions: normal lookup must work; SQL-like input must remain data on the safe route; another tenant's record must stay inaccessible. The vulnerable fixture is expected to demonstrate failure of those controls, so a passing teaching test can mean it successfully reproduced a vulnerability. Read the test, not just the green badge.

In a disposable branch, remove the safe query's tenant predicate while preserving parameter binding. The cross-tenant test must fail even though the interpolation-focused Semgrep rule may remain quiet. Restore the predicate and rerun. Do not publish that mutation or weaken the default branch.

## Exercise 2: optional ZAP passive baseline

Install a reviewed ZAP release from its official distribution. Record the version and add-on set. A native desktop installation can reach the loopback demo directly. For the packaged Docker baseline, the following is a **native Linux, same-host** example only; Docker Desktop host networking is not assumed.

With the app running on `127.0.0.1:8080`, first select and verify an official `ghcr.io/zaproxy/zaproxy` image digest using your trusted registry/tooling process. Set `ZAP_IMAGE` to that exact `ghcr.io/zaproxy/zaproxy@sha256:...` reference; do not paste an unreviewed digest or replace it with a moving tag in CI. Then run from the repository root in a POSIX shell:

```sh
mkdir -p reports
# ZAP_IMAGE must already contain your reviewed official image digest.
: "${ZAP_IMAGE:?Set the reviewed ZAP image digest first}"
case "$ZAP_IMAGE" in
  ghcr.io/zaproxy/zaproxy@sha256:*) ;;
  *) printf '%s\n' 'Use an official digest-pinned ZAP image.' >&2; exit 2 ;;
esac
docker run --rm --network host \
  --mount "type=bind,src=$(pwd)/reports,dst=/zap/wrk" \
  "$ZAP_IMAGE" zap-baseline.py \
  -t http://127.0.0.1:8080/ -m 1 -T 3 \
  -r baseline.html -J baseline.json
```

Only `reports/` is mounted; ensure the image's unprivileged user can write to it using scoped ownership rather than broad permission changes. Host networking permits wider host-network access; use a dedicated disposable lab host and do not run this on a sensitive shared machine. Never solve container reachability by binding the vulnerable app to `0.0.0.0`.

The baseline crawls and passively inspects responses; it does not actively probe SQL injection. Expect deployment/header findings in this HTTP teaching app. Review its exit status: `0` success, `1` at least one FAIL, `2` WARN without FAIL, `3` other failure. Do not append `|| true`, use `-I` to hide warning failures, or interpret an incomplete report as success. The example intentionally has no ignore file.

See [ZAP baseline options and exit codes](https://www.zaproxy.org/docs/docker/baseline-scan/). This walkthrough is optional and is not executed by the included workflow. Scanner/image validation is a separate step from the dependency-free tests.

## Exercise 3: design the real staging gate

Before adding authenticated or active scans to your own application:

1. Use an isolated staging deployment of the exact candidate artifact; inventory reachable endpoints and external integrations.
2. Obtain explicit scope and choose synthetic identities with distinct roles and tenants. Store ephemeral credentials in your approved secret system, never in this repo.
3. Prove login succeeded and protected routes were reached; fail if the session expires or coverage collapses to a login page.
4. Exclude destructive/external side effects by design; set concurrency/time bounds, abort conditions, reset procedures, and a scan owner.
5. Run targeted active tests only after approval. Keep reports access-controlled with short retention and redact tokens/cookies.
6. Fail the gate on scanner/runtime errors separately from the reviewed finding threshold. Ensure a known failing PR is actually blocked.

The included app has no login system, so it cannot demonstrate real authenticated ZAP sessions. Follow [ZAP authentication guidance](https://www.zaproxy.org/docs/getting-further/authentication/) for an application that does. Do not label simulated tenant context as authentication.

## Gate policy example

| Signal | Decision |
| --- | --- |
| Tool crash, unreachable target, expired login, or missing expected endpoint | Fail as **incomplete analysis**, not zero findings. |
| New confirmed high-impact issue within the agreed policy | Block and route to its owner; retain a reproducer. |
| Existing accepted risk | Named owner, rationale, compensating control, expiry, and retest; never a blanket permanent ignore. |
| Fixed code but old artifact still deployed | Not remediated in that environment. |

These are example decisions to adapt to your risk model, not an automatic policy applied by publishing this repository.
