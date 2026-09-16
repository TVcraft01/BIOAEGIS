# Contributing to BIOAEGIS

BIOAEGIS is a defensive security research project. Contributions should preserve the project's conservative security model and keep untrusted content as data rather than instructions.

## Before opening a change

- Read `README.md` and `SECURITY.md`.
- Keep tests deterministic and offline.
- Do not add code that executes scanned or fixture content.
- Do not add arbitrary shell execution to the specialist or validator path.
- Prefer small, reviewable changes with focused tests.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m bioaegis --version
python -m bioaegis redteam
```

## Pull requests

A good pull request should explain:

1. what changed;
2. why the change is needed;
3. what security boundary it affects;
4. how it was tested.

Security-sensitive changes should include regression coverage before they are considered complete.
