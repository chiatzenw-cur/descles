# Security policy

The Descles edge holds provider keys and tool credentials and sits between your agents and your systems.
We take reports about it seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately, by either:

- GitHub: **Security → Report a vulnerability** on this repository (private advisory), or
- email **outreach@descles.com** with "SECURITY" in the subject.

Include what you found, the version or commit, how to reproduce it, and the impact you expect. If you
need encrypted communication, say so in your first message and we will arrange it.

What to expect:

- acknowledgement within **3 business days**;
- an assessment and a planned fix date within **10 business days**;
- credit in the advisory if you want it, once a fix is released.

Please give us a reasonable time to fix an issue before disclosing it. Don't access data that isn't
yours, and don't degrade other people's use of a service while testing.

## Scope

In scope: this repository's code and the release artifacts built from it (binaries, the
`ghcr.io/chiatzenw-cur/descles-edge` image). Of particular interest:

- credential or content leaving the edge beyond what [docs/DATA-FLOWS.md](docs/DATA-FLOWS.md) lists;
- bypassing policy, approvals, grants or the key check;
- replaying or substituting an approved call;
- tampering with records the edge keeps;
- anything that makes a release differ from what this source builds.

Out of scope: vulnerabilities in model providers, MCP servers or harnesses themselves (report those to
their maintainers). Findings that require an already-compromised host are also out of scope.

## Supported versions

Security fixes go into the latest release. Until 1.0, upgrade to the newest version to receive them.
