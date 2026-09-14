# BIOAEGIS

**BIOAEGIS** is a biological-inspired defensive architecture built around one idea:

> **When a new threat appears, create a temporary specialist to solve it, keep the validated countermeasure, then discard the specialist.**

This repository currently contains **v0.1 — a safe simulation** of that architecture. It does **not** scan the host computer, execute malware, remove real files, or run arbitrary commands.

## Quick install

On Linux/macOS, the installer creates an isolated virtual environment under `~/.local/share/bioaegis` and installs the `bioaegis` launcher under `~/.local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/TVcraft01/BIOAEGIS/main/install.sh | bash
```

Then run:

```bash
bioaegis
```

If `bioaegis` is not found, `~/.local/bin` is not in your `PATH`. The installer prints the direct launcher path so you can run it immediately.

For a safer inspect-before-run workflow:

```bash
curl -fsSL https://raw.githubusercontent.com/TVcraft01/BIOAEGIS/main/install.sh -o /tmp/bioaegis-install.sh
less /tmp/bioaegis-install.sh
bash /tmp/bioaegis-install.sh
```

The installer requires `git` and `python3`. It does not require root privileges and does not install a system service.

## Terminal interface

`bioaegis` launches a standard-library `curses` interface. It is intentionally simulation-only:

```text
┌───────────────────────────────────────────────────────────┐
│ BIOAEGIS // DIGITAL IMMUNE SYSTEM // v0.1                │
├───────────────────────────────────────────────────────────┤
│ SYSTEM STATUS                                             │
│                                                           │
│ General Scanner     ACTIVE                                │
│ Immune Memory       0 responses                           │
│ Specialist          DISPOSABLE / STANDBY                  │
│ Validator           ACTIVE                                │
│ Host protection     SIMULATION ONLY                       │
├───────────────────────────────────────────────────────────┤
│ [S] Simulated scan     [M] Immune memory     [Q] Quit    │
└───────────────────────────────────────────────────────────┘
```

- `S` runs a simulated threat through the BIOAEGIS lifecycle.
- `M` displays the current immune-memory count.
- `Q` exits.

No real host files, processes, malware, or arbitrary shell commands are touched by the interface.

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
- `bioaegis/tui.py` — safe terminal interface
- `bioaegis/__main__.py` — `python -m bioaegis` entry point
- `install.sh` — user-local installer and launcher setup
- `tests/test_bioaegis.py` — learning/reuse and unsafe-response tests

## Development / tests

From a local checkout:

```bash
source .venv/bin/activate
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
- [x] Terminal interface
- [x] One-command user-local installer

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
