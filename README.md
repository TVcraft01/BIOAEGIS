# BIOAEGIS

<div align="center">

**A biological-inspired defensive security research platform.**

*Detect → Investigate → Validate → Contain → Remember*

[![CI](https://github.com/TVcraft01/BIOAEGIS/actions/workflows/test.yml/badge.svg)](https://github.com/TVcraft01/BIOAEGIS/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?logo=linux&logoColor=black)](https://kernel.org/)
[![Status](https://img.shields.io/badge/Status-Research%20Prototype-orange)](#current-status)

</div>

---

## Overview

BIOAEGIS explores a security architecture inspired by biological immune systems.

When a new suspicious behavior is observed, the system can create a **disposable specialist** to analyze the evidence. Only a **validated, declarative countermeasure** is retained. The specialist itself is discarded, while the validated response becomes part of the system's behavioral memory.

> **Core principle:** untrusted artifacts are treated as data, not instructions.

BIOAEGIS is designed as a controlled defensive research project. It is intentionally conservative: scanned files are never executed, responses are allow-listed, quarantine is reversible, and suspicious behavior is independently validated before a new response is remembered.

## Current status

**v0.5.1 — defensive research prototype**

Current capabilities include:

- read-only static file scanning;
- optional ClamAV integration for deep scans;
- SHA-256 identity and quarantine verification;
- reversible local quarantine and verified restore;
- deterministic disposable specialist;
- independent response validator with an allow-list;
- behavior-based immune memory with specificity-aware matching;
- fail-closed handling of malformed immune-memory data;
- Linux `/proc` process telemetry;
- common user-level persistence inspection;
- read-only TCP/UDP listener inventory;
- polling monitor combining defensive telemetry;
- inert adversarial regression fixtures, including EICAR.

### What it is not

BIOAEGIS is **not** a production antivirus or a replacement for mature endpoint security software. It does not provide guaranteed zero-day coverage, kernel-level detection, complete memory forensics, or complete network-intrusion detection.

---

## Architecture

```text
                         HOST / TEST VM
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
         FILE SCAN        RUNTIME SCAN    PERSISTENCE SCAN
              │                 │                 │
              └─────────────────┼─────────────────┘
                                ▼
                       GENERAL DETECTOR
                                │
                         new / unknown
                                │
                                ▼
                    DISPOSABLE SPECIALIST
                                │
                       candidate response
                                │
                                ▼
                         INDEPENDENT
                           VALIDATOR
                         │           │
                      accept       reject
                         │           └──────► no action
                         ▼
                       QUARANTINE
                         │
                  verify post-state
                         │
                         ▼
                    IMMUNE MEMORY
                         │
                         ▼
               FRESH GENERAL SCANNER
                         │
                 specialist discarded
```

### Security boundaries

**Scanner** — read-only analysis. No execution of scanned content.

**Specialist** — deterministic analysis baseline. It proposes only a predefined quarantine response.

**Validator** — rejects actions outside the explicit response allow-list.

**Quarantine** — moves files rather than deleting them and verifies SHA-256 before and after restoration.

**Immune memory** — stores validated responses, prefers more-specific behavioral rules, and fails closed when its data is malformed.

---

## Quick start

### Install

```bash
curl -fsSL "https://raw.githubusercontent.com/TVcraft01/BIOAEGIS/main/install.sh?$(date +%s)" | bash
```

The installer creates a user-local virtual environment, installs test dependencies, runs the test suite, and installs the `bioaegis` launcher into `~/.local/bin`.

### Verify

```bash
bioaegis --version
bioaegis test
bioaegis redteam
```

Expected current red-team coverage includes **8/8 inert tests**.

---

## CLI

### Scan

Detection only:

```bash
bioaegis scan ~/Downloads
```

Deep analysis:

```bash
bioaegis scan ~/Downloads --deep
```

Explicit reversible quarantine:

```bash
bioaegis scan ~/Downloads --quarantine
```

Normal mode focuses analysis on executables, known text/script formats, and unknown files that cheaply sniff as text. Deep mode inspects every regular file and may invoke ClamAV when available.

### Audit

Run a read-only combined audit:

```bash
bioaegis audit ~
bioaegis audit ~ --deep
```

The audit combines:

| Layer | Purpose |
|---|---|
| File | Static suspicious-content detection |
| Runtime | Suspicious process command-line indicators |
| Persistence | Common user startup locations |
| Network | Listening TCP/UDP sockets |

The audit does not kill processes, modify persistence, close sockets, or probe remote services.

### Monitor

Single pass:

```bash
bioaegis monitor ~/Downloads --once
```

Continuous polling:

```bash
bioaegis monitor ~/Downloads --interval 2
```

Enable reversible quarantine for newly detected file findings:

```bash
bioaegis monitor ~/Downloads --interval 2 --quarantine
```

For home-directory monitoring, file scans are throttled while process, persistence, and network telemetry continue each cycle.

### Quarantine recovery

List isolated files:

```bash
bioaegis quarantine list
```

Restore a reviewed file:

```bash
bioaegis quarantine restore ~/.local/share/bioaegis/quarantine/<file>.quarantined
```

Restore checks the quarantine record, verifies the stored SHA-256, refuses to overwrite an existing destination, restores the file, then verifies the resulting SHA-256 again.

---

## Detection model

BIOAEGIS uses bounded static analysis rather than executing artifacts.

### Normal mode

- bounded content reads;
- executable-file inspection;
- known text/script extension analysis;
- cheap text sniffing for otherwise unknown files;
- SHA-256 calculation for actual findings.

### Deep mode

- full regular-file coverage;
- larger analysis budget;
- SHA-256 identity;
- optional recursive ClamAV scan.

### Current behavioral indicators

The static engine currently includes detectors for several high-risk shell behaviors, including:

- download-to-shell patterns;
- download-to-evaluation patterns;
- base64 decoding indicators;
- reverse-shell indicators;
- destructive command indicators;
- EICAR anti-malware test signature;
- executable and hidden-executable signals.

A heuristic finding is **evidence, not proof of malware**.

---

## Immune memory

The memory layer stores the **validated countermeasure**, not the disposable specialist.

Behavioral matching means a response can be reused across variants that exhibit the same relevant behavior rather than requiring an identical file hash.

Memory matching is specificity-aware: a more specific behavioral trigger takes precedence over a broader earlier rule. Malformed memory is rejected rather than trusted.

The host lifecycle only commits a newly discovered countermeasure after successful quarantine and post-quarantine verification.

---

## Safe specialist design

The current host specialist is deliberately deterministic.

It does **not** accept instructions from the content it analyzes, generate arbitrary shell commands, or execute untrusted data. Its current baseline response is constrained to the validator's explicit allow-list:

```text
QUARANTINE_FILE
VERIFY_QUARANTINE
```

This creates a narrow security boundary that can later support more sophisticated local analysis without turning the specialist into an unrestricted command-generating agent.

---

## Red-team lab

Run the inert regression lab:

```bash
bioaegis redteam
```

The suite includes:

| Test | Purpose |
|---|---|
| Download → shell | Baseline behavior detection |
| Base64 decode | Encoded-command indicator |
| Reverse shell | Network-shell indicator |
| Destructive command | High-risk filesystem indicator |
| Multiline evasion | Shell line-continuation normalization |
| Download → eval | Alternative command structure |
| EICAR | Standard antivirus test signature |
| Memory variant reuse | Behavioral reuse across file variants |

**Nothing in the red-team lab is executed.**

For authorized live testing, use a disposable VM or dedicated test installation.

---

## EICAR regression fixture

BIOAEGIS includes the standard EICAR anti-malware test signature as an inert local fixture.

It is used to validate the complete defensive path:

```text
EICAR fixture
    ↓
static detection
    ↓
SHA-256 identity
    ↓
validated quarantine
    ↓
quarantine hash verification
    ↓
immune-memory update
    ↓
verified restore
```

The fixture is never executed by BIOAEGIS.

---

## Testing & CI

Run locally:

```bash
bioaegis test
bioaegis redteam
```

The GitHub Actions workflow runs the regression suite and CLI smoke tests for:

```text
pytest
--version
redteam
scan tests
audit tests
monitor tests --once
```

The current validated suite contains **19 automated tests**, and the latest complete CI validation passed all workflow steps.

---

## Project layout

```text
BIOAEGIS/
├── bioaegis/
│   ├── general_scanner.py      # Immune-memory lookup
│   ├── host_scanner.py         # Read-only filesystem scanner
│   ├── host_specialist.py      # Disposable deterministic specialist
│   ├── host_engine.py          # Detection / response lifecycle
│   ├── quarantine.py            # Reversible isolation + restore
│   ├── runtime_scanner.py      # Linux process telemetry
│   ├── persistence_scanner.py  # User persistence telemetry
│   ├── network_scanner.py      # Listener inventory
│   ├── audit.py                # Unified defensive audit
│   ├── monitor.py              # Polling monitor
│   ├── redteam.py              # Inert red-team lab
│   ├── validator.py            # Response allow-list validator
│   └── memory.py               # Persistent immune memory
├── tests/
│   ├── fixtures/
│   │   ├── eicar.com.txt       # Inert EICAR test fixture
│   │   └── README.md
│   └── test_bioaegis.py        # Regression suite
├── memory/
│   └── countermeasures.json    # Stored validated responses
├── .github/workflows/
│   └── test.yml                # CI workflow
├── install.sh                  # User-local installer
└── requirements-dev.txt        # Development/test dependencies
```

---

## Roadmap

### Research foundations

- [x] Read-only filesystem scanner
- [x] Normal/deep scan modes
- [x] SHA-256 identity and verification
- [x] Optional ClamAV integration
- [x] Disposable specialist baseline
- [x] Independent response validator
- [x] Reversible quarantine
- [x] Verified quarantine restore
- [x] Behavior-based immune memory
- [x] Process telemetry
- [x] Persistence telemetry
- [x] Listening-socket inventory
- [x] Unified audit
- [x] Polling monitor
- [x] Inert red-team regression lab
- [x] EICAR regression fixture
- [x] Continuous integration

### Next research areas

- [ ] Real-time filesystem/process monitoring
- [ ] Confidence scoring and evidence fusion
- [ ] Stronger behavioral clustering
- [ ] Memory integrity and signed policy data
- [ ] Privilege-separated system service
- [ ] Isolated malware-analysis sandbox
- [ ] Pluggable local specialist models
- [ ] Broader archive/container analysis

---

## Security philosophy

BIOAEGIS is built around a few deliberately strict rules:

> **Untrusted input never becomes an instruction.**

> **A specialist proposes; an independent validator decides.**

> **No validated cure is remembered before the defense is verified.**

> **When a safe response does not exist, the system should fail closed rather than guess.**

---

## Limitations

BIOAEGIS remains an experimental security project. Its current implementation is useful for controlled research, defensive engineering, and architecture experimentation, but it should **not** be represented as equivalent to mature commercial endpoint-security products.

In particular, it currently lacks complete kernel-level telemetry, full memory forensics, comprehensive network intrusion detection, continuous real-time enforcement, mature anti-tamper infrastructure, and broad malware-family coverage.

---

## License

See the repository license file for the applicable terms.
