# Tier 3 — test the assumptions the scanner cannot supply

Tier 3 retains the earlier checks and adds application-specific context. It is not simply a more expensive scanner or a higher severity threshold.

## Threat-model the lookup

| Element | Lab example | Production question |
| --- | --- | --- |
| Asset | Synthetic account records | Which records, actions, and metadata matter most? |
| Input boundary | HTTP email parameter | Which values can an untrusted caller control? |
| Query boundary | SQL execution | Can input change query structure? |
| Ownership boundary | Tenant-alpha vs tenant-beta | Is identity verified, tenant scope derived from it, and ownership checked on every access? |
| Runtime boundary | Local ephemeral process | Is the tested revision the one being released? What dependencies and deployment settings differ? |

The central exercise: binding SQL parameters prevents one injection mechanism, but does not by itself prevent cross-tenant reads. A syntactic SAST rule may catch concatenation without understanding ownership. A generic DAST scan may never try the right user-resource combination. Purpose-built assertions fill that gap.

## Authorization matrix

Apply this matrix to a real authenticated staging app with explicit permission. The local demo covers only a fixed tenant context; it does not implement all these roles or states.

| Actor and request | Expected result | Evidence |
| --- | --- | --- |
| Anonymous caller requests protected object | Denied without sensitive data | Response + server authorization decision |
| Tenant A user reads owned object | Allowed, limited to intended fields | Verified identity and expected object |
| Tenant A user reads tenant B object by known identifier | Denied | No foreign record or metadata leakage |
| Low-privilege user invokes administrative action | Denied | Action did not happen, not only an HTTP status |
| Expired or revoked session repeats a formerly allowed request | Denied | Session validity checked, no cached authority |
| Valid user replays a one-time business action | Rejected or safely idempotent, as designed | State and audit trail consistent with policy |

Do not stop at `403`: verify no side effect occurred. Conversely, an intentional `404` can be a valid non-disclosure policy. Document the application contract before asserting a status code.

## Hands-on exercises

1. Run the existing tests. Read the cross-tenant case and identify the invariant it protects.
2. On a disposable branch, remove only tenant scoping from the safe SQL. Observe the runtime test fail; compare with what the narrow static rule detects. Restore the original and rerun.
3. Add a synthetic record and a new ownership regression without changing the security contract. Review which actors/objects are still untested.
4. Add a new static pattern only when you can describe its threat, likely false positives, positive fixture, and safe negative fixture. Run rule tests before using it as a gate.
5. For your actual service, complete the [evidence worksheet](evidence-template.md) and map each high-risk abuse case to an automated test, a manual test, or an explicit gap.

Use [OWASP WSTG authorization testing](https://owasp.org/www-project-web-security-testing-guide/) and [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) to choose requirements. This repo's three tiers do not map one-to-one to ASVS verification levels and do not confer ASVS compliance.

## Measure what changes decisions

- Time from a confirmed issue to a verified deployed repair, by risk category.
- High-risk routes and actor/resource combinations with recorded test evidence.
- Scanner failure rate, session/coverage failures, and unresolved blind spots.
- Expired exceptions, repeat vulnerabilities, and false-positive decisions with rationale.

Avoid a single "security score" or target of zero alerts. More alerts can mean better coverage; fewer can mean the scanner stopped reaching the application. Retest after authentication, routing, build, and scanner-rule changes.
