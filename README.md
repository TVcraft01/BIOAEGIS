<div align="center">

# BIOAEGIS

### Biologically inspired defensive endpoint security research

**Detect → Investigate → Validate → Contain → Remember**

[![CI](https://github.com/TVcraft01/BIOAEGIS/actions/workflows/test.yml/badge.svg)](https://github.com/TVcraft01/BIOAEGIS/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-111111?logo=linux&logoColor=white)](https://kernel.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Research%20Prototype-orange)](#status)

A defensive research platform inspired by biological immune systems. BIOAEGIS combines event-driven filesystem observation, deterministic behavioral analysis, disposable investigation, independent response validation, reversible quarantine, integrity checks, and validated defensive memory.

</div>

---

## Status

**Current release: `0.7.0`**

BIOAEGIS is an **experimental defensive security research platform**. It is not a proven replacement for established antivirus or EDR products.

The 0.7.0 release focuses on four engineering goals: continuous local protection, stronger behavioral evidence, tamper detection, and a fail-closed signed update path.

### Implemented baseline

| Area | Status | Notes |
| --- | :---: | --- |
| Bounded static analysis | Done | Non-executing normal/deep scanning |
| Behavioral evidence fusion | Done | Deterministic confidence levels |
| Archive inspection | Done | ZIP/JAR/WHEEL/APK/TAR without extraction |
| Runtime telemetry | Done | Linux `/proc`, read-only |
| Persistence telemetry | Done | User-level startup locations |
| Network telemetry | Done | Listener inventory, no remote probing |
| Inotify event monitoring | Done | Recursive filesystem event source |
| Continuous protection service | Done | systemd user service + periodic safety sweeps |
| Automatic containment gate | Done | Automatic quarantine requires HIGH confidence and validated response |
| Reversible quarantine | Done | Hash-verified isolation and restoration |
| Immune memory integrity | Done | HMAC signature, fail closed on tampering |
| Installation integrity | Done | Signed manifest covers active installed package and deployment assets |
| Desktop console | Done | Native QtWebEngine on Linux |
| Automatic startup | Done | Background protection + desktop console |
| Signed update verifier | Done | Ed25519 manifest + SHA-256 artifact verification |
| Automatic update timer | Done | Runs, but remains fail-closed until a signed release manifest is enabled |
| Regression suite | Done | Static, lifecycle, telemetry, tamper, archive, EICAR coverage |
| Independent AV testing | Not yet | Requires external third-party evaluation |
| External security audit | Not yet | Requires independent assessor |

## What runs automatically

The official installer configures BIOAEGIS as a user-level Linux application rather than a command you must manually activate.

After installation:

```text
Login
  ├─ BIOAEGIS protection service starts
  │    ├─ filesystem events → scan → validate → high-confidence containment
  │    ├─ periodic safety sweep
  │    └─ runtime / persistence / network telemetry
  │
  └─ BIOAEGIS Security Console starts
       └─ displays live protection state and history
```

Closing the graphical console does **not** stop the protection service.

The installer also registers BIOAEGIS in the desktop application menu and schedules the signed-update worker.

## Architecture

```text
                   USER WORKSTATION
                          │
          ┌───────────────┼────────────────┐
          │               │                │
      FILE EVENTS      /proc         PERSISTENCE
          │               │                │
          └───────────────┼────────────────┘
                          ▼
                  BEHAVIOR / EVIDENCE
                          │
                ┌─────────┴─────────┐
                │                   │
             ANALYZE             TELEMETRY
                │                   │
                └─────────┬─────────┘
                          ▼
                 CONFIDENCE FUSION
                          │
                 known / unknown rule
                     │          │
                     ▼          ▼
              IMMUNE MEMORY   SPECIALIST
                                  │
                                  ▼
                           CANDIDATE RESPONSE
                                  │
                                  ▼
                           INDEPENDENT VALIDATOR
                              │           │
                           reject       accept
                              │           │
                              ▼           ▼
                           NO ACTION   POLICY GATE
                                          │
                              HIGH confidence only
                                          │
                                          ▼
                                      QUARANTINE
                                          │
                                          ▼
                                   SHA-256 VERIFY
                                          │
                                          ▼
                                   IMMUNE MEMORY
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the trust model, process boundaries, and failure modes.

## Protection model

### Real-time protection

Linux `inotify` watches protected user directories recursively. File creation, modification, and move events are analyzed immediately, while periodic sweeps provide a second layer if an event queue overflows or an event is missed.

Automatic containment is deliberately stricter than manual scanning: a finding must have **HIGH confidence** and pass the independent validator before automatic quarantine is allowed.

### Behavioral detection

The static engine now combines multiple indicators instead of treating every indicator as equivalent. Current signals include:

- download-to-shell and download-to-evaluation patterns;
- shell/interpreter command execution patterns;
- simple obfuscation and base64 decoding indicators;
- reverse-shell indicators;
- destructive commands;
- suspicious temporary execution;
- suspicious persistence patterns;
- archive path traversal, links, oversized members, and suspicious script content;
- EICAR test signature;
- optional ClamAV findings in deep scans.

A behavioral signal is **evidence, not proof of malware**.

### Tamper resistance

BIOAEGIS keeps two distinct integrity controls:

1. **Immune memory integrity** — HMAC-signed memory entries are rejected if they are modified.
2. **Installation integrity** — a signed local manifest hashes the active installed package plus critical deployment assets. The protection service periodically verifies that manifest and reports `degraded` when integrity is lost.

These mechanisms provide tamper **detection**. They are not a secure root of trust against a fully privileged attacker who can replace both the application and its trust material.

### Secure updates

BIOAEGIS has a fail-closed update channel:

1. retrieve a small signed release manifest;
2. verify the Ed25519 signature against the pinned public key;
3. compare the release version;
4. download the release artifact with a size limit;
5. verify its SHA-256 digest;
6. install the verified package;
7. rebuild the installation integrity manifest;
8. restart the protection service after a successful update.

The automatic update worker is currently **disabled for actual release application until the signing workflow and release key are configured**. An unsigned or malformed manifest results in no update.

## Dashboard / application

The security console is local and loopback-only by default.

The official Linux installer registers:

- `BIOAEGIS Security Console` in the application menu;
- desktop-login autostart;
- a native QtWebEngine window;
- background protection independent from the GUI.

The console shows protection state, validated memory, quarantine records, scan results, and local telemetry.

## Install once

From any directory:

```bash
curl -fsSL https://raw.githubusercontent.com/TVcraft01/BIOAEGIS/main/install.sh | bash
```

After installation, BIOAEGIS is configured to start itself. No manual activation command is required.

For development installations, install the package directly with pip instead.

## CLI

The CLI remains available for development and explicit analysis:

```bash
bioaegis --version
bioaegis scan ~/Downloads
bioaegis scan ~/Downloads --deep
bioaegis scan ~/Downloads --quarantine
bioaegis audit ~/Downloads
bioaegis redteam
bioaegis test
```

Continuous protection is normally managed by the installed user service rather than by manually launching `bioaegis protect`.

## Validation and evidence

BIOAEGIS deliberately separates **implemented controls** from **evidence that those controls work against real malware**.

The repository contains:

- deterministic unit and integration tests;
- EICAR regression coverage;
- inert red-team fixtures;
- installation-tamper regression tests;
- update-signature verification logic;
- a benchmark harness for measuring detection, false positives, and runtime overhead.

The repository does **not** currently claim:

- an independently measured malware detection rate;
- a measured zero-day detection rate;
- a validated false-positive rate on a representative corpus;
- professional-antivirus-level CPU, RAM, or I/O performance;
- an external security audit.

Those require controlled datasets, reproducible methodology, independent reviewers, and published results. See [`docs/VALIDATION.md`](docs/VALIDATION.md).

## Development

Requirements:

- Linux
- Python 3.12+
- `pytest` for testing
- ClamAV is optional
- PySide6/pywebview are installed by the Linux desktop extra
- `cryptography` is installed by the update-verification extra

Local checks:

```bash
python -m pip install -e .
python -m pip install -r requirements-dev.txt
python -m compileall -q bioaegis
python -m pytest -q
bioaegis redteam
```

GitHub Actions runs package installation, source compilation, the full regression suite, and CLI smoke tests.

## Project layout

```text
BIOAEGIS/
├── bioaegis/                  # Runtime package
│   ├── host_scanner.py        # Static + behavioral host analysis
│   ├── host_engine.py         # Detection / validation / containment lifecycle
│   ├── protection.py          # Continuous protection service
│   ├── realtime.py             # Linux inotify source
│   ├── confidence.py           # Evidence fusion
│   ├── runtime_scanner.py      # Process telemetry
│   ├── persistence_scanner.py  # Persistence telemetry
│   ├── network_scanner.py      # Listener inventory
│   ├── archive_scanner.py      # Safe container inspection
│   ├── memory.py               # Signed immune memory
│   ├── tamper.py               # Installation integrity manifest
│   ├── updates.py              # Signed update verification
│   ├── dashboard.py            # Local dashboard server
│   ├── app.py                  # Native desktop launcher
│   └── dashboard_static/       # Frontend assets
├── tests/                      # Regression tests
├── benchmarks/                 # Measurement harnesses
├── docs/                       # Architecture + validation docs
├── service/                    # systemd service/timer units
├── updates/                    # Release manifest + public trust anchor
├── install.sh                  # User-local installer
├── pyproject.toml              # Package metadata
└── SECURITY.md                 # Security reporting policy
```

## Roadmap

The next stage is evidence and hardening rather than marketing claims:

- [ ] independent malware-detection evaluation;
- [ ] large benign corpus false-positive study;
- [ ] CPU / RAM / disk / latency benchmarks on representative hardware;
- [ ] external security review / audit;
- [ ] privilege-separated service with authenticated IPC;
- [ ] stronger external trust root for policy and memory;
- [ ] kernel telemetry / prevention research;
- [ ] complete memory-forensics pipeline;
- [ ] real isolated malware detonation lab;
- [ ] mature adversarial ML evaluation;
- [ ] public reproducible benchmark reports.

## Limitations

BIOAEGIS does **not** claim:

- complete malware detection;
- guaranteed zero-day protection;
- kernel-level prevention;
- complete memory forensics;
- production-grade malware detonation isolation;
- immunity to a fully privileged local attacker;
- professional-antivirus equivalence without independent evidence.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system and trust architecture
- [`docs/VALIDATION.md`](docs/VALIDATION.md) — measurement methodology and current evidence
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution workflow
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting
- [`service/bioaegis-user.service`](service/bioaegis-user.service) — protection service
- [`service/bioaegis-update.timer`](service/bioaegis-update.timer) — signed update schedule

## License

BIOAEGIS is released under the [MIT License](LICENSE).

---

<div align="center">

**BIOAEGIS is research software.**

*Observe carefully. Validate independently. Remember only what has been verified.*

</div>
