# Contributing to HEVEC

Thanks for helping improve the homomorphically encrypted vector database! This short guide explains how to set up a dev environment, propose changes, and report issues.

## Getting started
- Clone the repo and create the recommended Conda env: `conda env create -f server/conda/HEVEC-dev.yml && conda activate HEVEC-dev`.
- Build the core + Python binding for local use: `cd server && cmake -S . -B build -DBUILD_PYTHON=ON && cmake --build build --config Release && pip install -e .`.
- Optional Node binding: `cd client/node && npm install && npm run build:hevec-native`.

## Development conventions
- Language levels: C++20, Python 3.10+, Node 20+. Enable warnings where possible.
- Style: keep existing formatting; add concise comments only where non-obvious. Prefer small, focused PRs.
- Tests: add or update minimal regression tests for new logic. If adding a feature, include a repro script under `server/example/` or a unit test when a test harness is introduced.
- Dependencies: avoid adding global requirements unless necessary; document any new external assets or models.

## Making changes
1. Open an issue first for substantial features/changes to align on scope.
2. Branch from `main`, keep commits tidy (logical grouping, clear messages).
3. Ensure build succeeds (`cmake --build build --config Release`) and example scripts you touched still run.
4. Update docs/usage strings when behaviors or flags change.
5. Submit a PR referencing the issue; include a short test/verification note in the description.

## Communication
- Questions and bugs: open a GitHub issue with repro steps and environment info.
- Security-sensitive findings: follow the process in `SECURITY.md` (private channel, not public issues).

## Code of conduct
Participation is governed by `CODE_OF_CONDUCT.md`. Please read it before engaging.
