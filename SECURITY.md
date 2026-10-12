# Security policy

ai-agent-audit reads credentials, agent sessions and configuration on the machine it runs on, so a
weakness in it matters. Examples: a secret value written to a report or to the terminal, a file
written outside the output directory, a crafted repository or MCP config that makes the audit run a
command, or a report field an AI agent could be tricked by.

## Reporting

Please do not open a public issue. Use GitHub's private vulnerability reporting
(Security tab → "Report a vulnerability") or email bartek@devince.dev with:

- what you found and its impact,
- the smallest steps or fixture that reproduces it,
- the commit you tested.

Never include real credentials. Use fake values (the test suite's `fake_secret` helper shows how).

You get a reply within 7 days. Fixes land on `main` with a regression test and a CHANGELOG entry;
you are credited unless you ask not to be.

## Scope

In scope: everything under `scripts/` and `tests/`. Out of scope: false positives and missed
detections (open a normal issue for those), and the landing page (report those at
https://github.com/bartek-filipiuk/local-security-landing).
