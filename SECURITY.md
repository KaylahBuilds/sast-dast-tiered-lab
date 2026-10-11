# Safe use and security reporting

This repository intentionally contains SQL injection and missing-tenant-scope examples. Do not deploy the demo to a shared or public network. Keep its fixed loopback binding, synthetic database, and local-only workflow. Do not use production credentials, real personal data, tunnels, port forwarding, or cloud deployments.

The safe endpoint fixes selected demonstrated behaviors. It is not a hardened web framework or complete authorization system. Never use it as a production starter app.

Only scan systems you own or are explicitly authorized to test. Authorization must cover targets, routes, identities, timing, techniques, and possible side effects. Passive response inspection is not the same as making no requests: a crawler still interacts with the application. Active scanning can change state or trigger workflows.

Never commit credentials. Do not attach raw reports with cookies, tokens, personal data, request bodies, or internal hosts to public issues. Ignore rules are convenience, not a secret-prevention guarantee. Review the exact staged files before every publication.

For unintended issues in this repository, contact the maintainer through the contact link on [kaylahbuilds.io](https://kaylahbuilds.io/). Send a minimal, sanitized description first; agree on a private channel before sharing sensitive proof. Do not test the public website or third-party services to demonstrate this lab's intentional weaknesses.
