# Security Policy

## Supported versions
This is an active research codebase. Only the `main` branch is maintained; no backporting to older tags is guaranteed.

## Reporting a vulnerability
- **Preferred:** Use GitHub’s Private Vulnerability Reporting or Security Advisory draft for this repository (Security tab → “Report a vulnerability”).  
- **Email fallback:** jaejin.lee@snu.ac.kr (project maintainer listed in `server/setup.py`).
- Please do **not** open a public issue for sensitive reports.

### What to include
- A clear description of the issue, impact, and affected components.
- Repro steps (commands, inputs, environment).
- Any mitigations you have identified.

### Response expectations
- We aim to acknowledge reports within 7 days.
- We will coordinate on a fix and public disclosure timeline before publishing details.

## Keys, data, and model handling
Avoid posting private keys, proprietary datasets, or model checkpoints in issues/PRs. If an incident involves leaked secrets, rotate them and contact the maintainers via the channels above.
