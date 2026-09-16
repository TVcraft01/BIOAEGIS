<div align="center">

# BIOAEGIS

### Biologically inspired defensive security research

**Detect → Investigate → Validate → Contain → Remember**

[![CI](https://github.com/TVcraft01/BIOAEGIS/actions/workflows/test.yml/badge.svg)](https://github.com/TVcraft01/BIOAEGIS/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-111111?logo=linux&logoColor=white)](https://kernel.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Research%20Prototype-orange)](#status)

A defensive research platform exploring an artificial-immune-system approach to host security: suspicious behavior is investigated by a disposable specialist, independently validated, safely contained, and only then remembered.

</div>

---

## Why BIOAEGIS?

Traditional signature-only thinking asks whether a file is known.
BIOAEGIS explores a different question:

> **Does this behavior match something the system has learned to defend against?**

The project combines deterministic static analysis, behavioral memory, reversible quarantine, host telemetry, and explicit security boundaries. It is intentionally conservative: untrusted artifacts are data, not instructions.

## Status

**Current release: `0.6.0`**

BIOAEGIS is an **experimental security research platform**, not a production antivirus or EDR replacement.

### Implemented research baseline

| Area | Status | Notes |
| --- | :---: | --- |
| Static file analysis | Done | Bounded, non-executing analysis |
| Normal / deep scanning | Done | Deep mode can use ClamAV when installed |
| SHA-256 identity | Done | Used for findings and quarantine verification |
| Disposable specialist | Done | Deterministic baseline |
| Independent validator | Done | Explicit response allow-list |
| Reversible quarantine | Done | Move + verify + restore |
| Behavioral immune memory | Done | Specificity-aware matching, fail-closed parsing |
| Confidence / evidence fusion | Done | Deterministic research baseline |
| Behavior clustering | Done | Explainable Jaccard similarity baseline |
| Runtime telemetry | Done | Linux `/proc`, read-only |
| Persistence telemetry | Done | User-level startup locations |
| Network telemetry | Done | Listener inventory, no probing |
| Polling monitor | Done | Optional quarantine |
| Linux inotify event source | Done | Near-real-time event source |
| Archive inspection | Done | Safe inspection module, no extraction |
| Specialist provider API | Done | Narrow research extension point |
| Local integrity primitive | Done | HMAC-based, not a trust root |
| Analysis workspace | Done | Non-executing research sandbox |
| Hardened user service | Done | systemd template |
| Local security dashboard | Done | Loopback HTTP console with read-only APIs |
| Red-team regression lab | Done | Inert fixtures only |
| EICAR regression | Done | Standard anti-malware test fixture |

## Architecture

```text
                         HOST / LAB
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
      FILE SCAN        RUNTIME SCAN      PERSISTENCE
          │                 │                 │
          └─────────────────┼─────────────────┘
                            ▼
                     EVIDENCE / SIGNALS
                            │
                            ▼
                    GENERAL DETECTOR
                            │
                   known / new behavior
                            │
                ┌───────────┴───────────┐
                │                       │
             known                    unknown
                │                       │
                ▼                       ▼
         IMMUNE MEMORY           DISPOSABLE SPECIALIST
                                        │
                                        ▼
                                  CANDIDATE RESPONSE
                                        │
                                        ▼
                                  INDEPENDENT VALIDATOR
                                    │             │
                                  reject        accept
                                    │             │
                                    ▼             ▼
                                NO ACTION      QUARANTINE
                                                   │
                                                   ▼
                                             VERIFY STATE
                                                   │
                                                   ▼
                                            IMMUNE MEMORY
                                                   │
                                                   ▼
                                           FRESH SCANNER
```

For the detailed trust model, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Security model

BIOAEGIS is built around a few explicit boundaries:

**Scanners are read-only.** Scanned content is inspected but never executed.

**The specialist is not trusted.** It can propose a predefined response, but it does not get arbitrary shell access.

**The validator is independent.** Only actions on the explicit response allow-list can proceed.

**Quarantine is reversible.** Files are moved into controlled storage rather than deleted, with SHA-256 verification before and after restoration.

**Memory stores validated defenses.** The disposable specialist is not persisted as authority.

**Invalid state fails closed.** Malformed memory or unsupported responses do not become autonomous actions.

## What it does

### Static analysis

Normal mode performs bounded analysis of executables, known text/script formats, and files that cheaply sniff as text. Deep mode expands coverage and can invoke recursive ClamAV scanning when available.

Current behavioral indicators include download-to-shell, download-to-evaluation, base64 payload patterns, reverse-shell indicators, destructive-command indicators, and the EICAR test signature.

A detection signal is **evidence, not proof of malware**.

### Behavioral immune memory

Validated responses are associated with behavioral triggers rather than only exact file hashes. Matching prefers the most specific available trigger, allowing a more precise defense to take precedence over a broad earlier rule.

Malformed memory data is rejected instead of being trusted.

### Evidence fusion

`bioaegis.confidence` combines deterministic indicators into a `LOW`, `MEDIUM`, or `HIGH` confidence result. Confidence is a reporting/prioritization signal; it does not bypass validation.

### Behavior clustering

`bioaegis.behavior` provides a deliberately simple Jaccard-similarity baseline for grouping related behavior sets without an opaque machine-learning model.

### Host telemetry

BIOAEGIS can inspect:

- Linux process command lines through `/proc`;
- common user persistence locations;
- listening TCP/UDP sockets;
- filesystem changes through polling and a Linux inotify event source.

The telemetry components do not kill processes, execute command lines, probe remote hosts, or close sockets.

### Safe archive inspection

`bioaegis.archive_scanner` inspects common ZIP/JAR/WHEEL/APK and TAR-family containers without extracting or executing their contents. It can identify conditions such as path traversal, dangerous links, oversized members, and simple suspicious script content.

### Research sandbox

`bioaegis.sandbox` creates a restricted, non-executing analysis workspace with an explicit manifest. It is **not** a production malware detonation sandbox and should not be treated as one.

## Dashboard

BIOAEGIS now includes a local security-console dashboard designed for a defensive workstation or lab.

Start it with:

```bash
bioaegis dashboard
```

Then open:

```text
http://127.0.0.1:8765
```

The console provides a browser-based overview of engine state, immune-memory count, quarantine state, safeguards, and the detection lifecycle. It refreshes local state automatically and exposes small read-only JSON endpoints for health, memory, and quarantine data.

The dashboard binds to **loopback by default**. It does not expose arbitrary remote-control endpoints and does not provide a web route for executing commands or changing security policy.

Custom bind/port:

```bash
bioaegis dashboard --host 127.0.0.1 --port 8765
```

## CLI

Install the package in editable mode during development:

```bash
python -m pip install -e .
```

The main commands are:

```bash
bioaegis --version
bioaegis dashboard
bioaegis scan ~/Downloads
bioaegis scan ~/Downloads --deep
bioaegis scan ~/Downloads --quarantine
bioaegis audit ~/Downloads
bioaegis monitor ~/Downloads --interval 2
bioaegis monitor ~/Downloads --interval 2 --quarantine
bioaegis quarantine list
bioaegis quarantine restore <quarantine-file>
bioaegis redteam
bioaegis test
```

Quarantine is deliberately opt-in. Detection-only scanning is the default.

## Red-team lab

```bash
bioaegis redteam
```

The red-team suite contains inert regression cases for shell indicators, multiline/evasion patterns, behavior-memory reuse, and EICAR.

**Nothing in the repository's red-team fixtures is executed.**

For live malware research, use a separate hardened lab or disposable VM.

## EICAR regression

The repository contains the standard EICAR anti-malware test signature as an inert local fixture. The regression path verifies detection, SHA-256 identity, quarantine, memory update, and restoration without executing the fixture.

## Service hardening

`service/bioaegis-user.service` provides a controlled user-level systemd template with hardening directives including `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, `RestrictSUIDSGID`, `LockPersonality`, and `MemoryDenyWriteExecute`.

This is **not** privilege separation. A production endpoint implementation would still require stronger isolation, authenticated IPC, dedicated service identities, and additional platform-specific controls.

## Development

### Requirements

- Linux
- Python 3.12+
- `pytest` for the test suite
- ClamAV is optional

### Local verification

```bash
python -m pip install -e .
python -m pip install -r requirements-dev.txt
python -m compileall -q bioaegis
python -m pytest -q
bioaegis redteam
```

GitHub Actions runs package installation, source compilation, the full test suite, and CLI smoke tests.

## Project layout

```text
BIOAEGIS/
├── bioaegis/                  # Application package
│   ├── host_scanner.py        # Static host scanning
│   ├── host_engine.py         # Detection / response lifecycle
│   ├── host_specialist.py     # Disposable deterministic specialist
│   ├── validator.py            # Response policy boundary
│   ├── memory.py               # Persistent immune memory
│   ├── dashboard.py             # Local web security console
│   ├── confidence.py           # Evidence fusion
│   ├── behavior.py             # Behavior similarity / clustering
│   ├── archive_scanner.py      # Safe archive inspection
│   ├── integrity.py            # Local integrity primitive
│   ├── specialist_api.py       # Specialist provider interface
│   ├── sandbox.py               # Non-executing analysis workspace
│   ├── realtime.py              # Linux inotify event source
│   ├── quarantine.py            # Reversible containment
│   ├── runtime_scanner.py       # Process telemetry
│   ├── persistence_scanner.py  # Persistence telemetry
│   ├── network_scanner.py       # Listener inventory
│   ├── monitor.py               # Polling monitor
│   ├── audit.py                 # Unified audit
│   └── redteam.py               # Inert adversarial regression lab
├── tests/                      # Automated regression coverage
├── docs/                       # Design and architecture references
├── service/                    # systemd deployment template
├── memory/                     # Persistent validated responses
├── .github/                    # CI and contribution workflow
├── pyproject.toml              # Package metadata and tooling
├── install.sh                  # User-local bootstrap installer
├── requirements-dev.txt        # Development dependencies
├── SECURITY.md                 # Security reporting policy
├── CONTRIBUTING.md             # Contribution guide
├── CODE_OF_CONDUCT.md          # Community standards
└── LICENSE                     # MIT license
```

## Roadmap

The core research baseline is implemented. The next stage is about turning that baseline into a genuinely production-grade platform rather than adding more surface area prematurely.

- [ ] Privilege-separated service with authenticated IPC
- [ ] Stronger policy signing / external trust anchors
- [ ] Kernel-level telemetry and prevention research
- [ ] Complete memory-forensics pipeline
- [ ] Real detonation sandbox with verified isolation
- [ ] Mature local ML components with adversarial evaluation
- [ ] Larger archive/container coverage
- [ ] Continuous adversarial benchmark corpus
- [ ] Packaging and release automation

## Limitations

BIOAEGIS does **not** claim:

- complete malware detection;
- guaranteed zero-day protection;
- kernel-level prevention;
- complete memory forensics;
- production-grade malware detonation isolation;
- protection against a fully privileged local attacker.

Those limitations are part of the design, not hidden assumptions.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — trust model and data flow
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development and contribution workflow
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting
- [`service/bioaegis-user.service`](service/bioaegis-user.service) — hardened user-service template

## License

BIOAEGIS is released under the [MIT License](LICENSE).

---

<div align="center">

**BIOAEGIS is research software.**

*Observe carefully. Validate independently. Remember only what has been verified.*

</div>
