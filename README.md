# BIOAEGIS

**BIOAEGIS** is a biological-inspired defensive architecture built around one idea:

> **When a new threat appears, create a temporary specialist to solve it, keep the validated countermeasure, then discard the specialist.**

This repository currently contains **v0.1 — a safe simulation** of that architecture. It does **not** scan the host computer, execute malware, remove real files, or run arbitrary commands.

## Architecture

```text
                    ┌──────────────────────┐
                    │   GENERAL SCANNER     │
                    │  detects known/new    │
                    │       behavior       │
                    └──────────┬───────────┘
                               │
                         unknown threat
                               │
                               ▼
                    ┌──────────────────────┐
                    │  DISPOSABLE SPECIALIST│
                    │    investigate only   │
                    └──────────┬───────────┘
                               │
                       candidate cure
                               │
                               ▼
                    ┌──────────────────────┐
                    │      VALIDATOR       │
                    │ independent safety   │
                    │       checks         │
                    └──────────┬───────────┘
                               │
                    accepted │       rejected
                               │            └──► quarantine/escalation
                               ▼
                    ┌──────────────────────┐
                    │   IMMUNE MEMORY      │
                    │ stores only trigger  │
                    │ + validated response │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  FRESH GENERAL       │
                    │  SCANNER / HOT SWAP  │
                    └──────────────────────┘

                    SPECIALIST → DISCARDED
```

## Core principles

1. **The specialist is a researcher, not an authority.** Its proposal must pass independent validation.
2. **No arbitrary commands.** v0.1 uses a tiny allow-listed countermeasure language containing only simulated actions.
3. **Memory stores the cure, not the specialist.** The specialist itself is not serialized or retained.
4. **Behavior matters more than a single hash.** The prototype can reuse a response for a variant with the same behavioral signature.
5. **Failure is safer than guessing.** An unsafe or unverifiable proposal is rejected.
6. **Hot-swap instead of blind replacement.** The general scanner is rebuilt only after validated memory is available.

## Current implementation

- `bioaegis/general_scanner.py` — memory-aware general scanner
- `bioaegis/specialist.py` — disposable specialist simulation
- `bioaegis/validator.py` — independent response validation
- `bioaegis/memory.py` — persistent validated countermeasure memory
- `bioaegis/lifecycle.py` — detect → specialist → validate → remember → fresh general scanner
- `bioaegis/models.py` — threat, response, and validation models
- `tests/test_bioaegis.py` — learning/reuse and unsafe-response tests

## Run the prototype

```bash
python -m pytest -q
```

The tests use **simulated threats only**. Nothing in v0.1 is intended to be deployed as a real endpoint antivirus.

## Roadmap

### v0.1 — Immune-system simulation
- [x] General scanner
- [x] Disposable specialist
- [x] Independent validator
- [x] Persistent immune memory
- [x] Variant-aware behavioral trigger
- [x] Safe simulated countermeasures

### v0.2 — Defensive sandbox
- [ ] Real isolated analysis environment
- [ ] Structured behavioral telemetry
- [ ] Reversible quarantine abstraction
- [ ] Stronger countermeasure validation
- [ ] Persistence/reboot simulation

### v0.3 — Research prototype
- [ ] Pluggable detection engines
- [ ] Countermeasure confidence scoring
- [ ] Mutation/variant handling
- [ ] Memory integrity protection
- [ ] Audit trail and rollback

### Later
Real endpoint integration should only be introduced with strict isolation, least privilege, signed/validated actions, rollback, and explicit safety checks.

## Status

**Experimental research prototype — not an antivirus.**

BIOAEGIS is intended to explore whether an adaptive, immune-inspired lifecycle can safely learn **defensive responses** without permanently retaining the agent that discovered them.
