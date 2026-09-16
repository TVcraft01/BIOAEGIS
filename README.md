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
- deterministic confidence scoring and evidence fusion;
- deterministic behavior similarity and clustering;
- local signed-policy/integrity primitives;
- safe archive/container inspection without extraction or execution;
- Linux `/proc` process telemetry;
- common user-level persistence inspection;
- read-only TCP/UDP listener inventory;
- polling monitor and Linux inotify near-real-time event source;
- constrained specialist-provider API;
- non-executing isolated analysis workspace;
- hardened user-systemd service template;
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
                       EVIDENCE FUSION
                                │
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

**Integrity layer** — provides local HMAC-backed integrity for policy/memory data. This is a research baseline, not a hardware-backed trust root.

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

```bash
bioaegis scan ~/Downloads
bioaegis scan ~/Downloads --deep
bioaegis scan ~/Downloads --quarantine
```

Normal mode focuses analysis on executables, known text/script formats, and unknown files that cheaply sniff as text. Deep mode inspects every regular file and may invoke ClamAV when available.

### Audit

```bash
bioaegis audit ~
bioaegis audit ~ --deep
```

The audit combines file/static findings, suspicious process command lines, common user persistence locations, and listening TCP/UDP sockets. It does not kill processes, modify persistence, close sockets, or probe remote services.

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

The Linux inotify module provides a near-real-time event source for targeted directories; analysis still flows through the normal read-only scanner.

### Quarantine recovery

```bash
bioaegis quarantine list
bioaegis quarantine restore ~/.local/share/bioaegis/quarantine/<file>.quarantined
```

Restore checks the quarantine record, verifies the stored SHA-256, refuses to overwrite an existing destination, restores the file, then verifies the resulting SHA-256 again.

---

## Detection model

BIOAEGIS uses bounded static analysis rather than executing artifacts.

### Evidence fusion

The confidence engine combines independent behavioral signals and external evidence into a deterministic `LOW` / `MEDIUM` / `HIGH` confidence result. Confidence affects prioritization and reporting; it does not bypass the validator's response allow-list.

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

### Behavioral indicators

The static engine currently includes detectors for several high-risk shell behaviors, including download-to-shell, download-to-evaluation, base64 decoding, reverse-shell indicators, destructive command indicators, and the EICAR anti-malware test signature.

A heuristic finding is **evidence, not proof of malware**.

---

## Behavior clustering

`bioaegis.behavior` provides deterministic Jaccard similarity and lightweight clustering of behavior sets. This is intentionally simple and explainable: it provides a baseline for grouping variants without introducing a trainable model or opaque inference layer.

---

## Immune memory

The memory layer stores the **validated countermeasure**, not the disposable specialist.

Behavioral matching means a response can be reused across variants that exhibit the same relevant behavior rather than requiring an identical file hash.

Memory matching is specificity-aware: a more specific behavioral trigger takes precedence over a broader earlier rule. Malformed memory is rejected rather than trusted.

The integrity layer can authenticate policy/memory payloads using a local 256-bit key with restrictive filesystem permissions. Because the key is local, this is integrity detection rather than protection against a fully privileged attacker.

---

## Safe specialist design

The current host specialist is deliberately deterministic.

It does **not** accept instructions from the content it analyzes, generate arbitrary shell commands, or execute untrusted data. Its response is constrained to the validator's explicit allow-list:

```text
QUARANTINE_FILE
VERIFY_QUARANTINE
```

`bioaegis.specialist_api` provides a narrow provider interface so future local models can be plugged in without giving them direct execution authority. Model-backed specialists remain optional research components rather than trusted security boundaries.

---

## Archive and container analysis

BIOAEGIS now performs bounded inspection of common ZIP/JAR/WHEEL/APK and TAR-family containers without extracting or executing their contents.

It can identify research-relevant conditions such as archive path traversal, dangerous archive links, oversized members, and simple suspicious shell content inside script members.

This is deliberately safer than automatically extracting untrusted archives on the host.

---

## Isolated analysis workspace

`bioaegis.sandbox.AnalysisSandbox` provides a restricted analysis workspace and explicit manifest stating that sample execution and network access are disabled.

This is a **non-executing research sandbox**, not a claim of full malware detonation isolation. Actual executable malware analysis should remain in a separately hardened VM or dedicated sandbox platform.

---

## Red-team lab

```bash
bioaegis redteam
```

The suite includes baseline shell indicators, multiline evasion, download-to-evaluation, EICAR, and behavior-memory variant reuse.

**Nothing in the red-team lab is executed.**

For authorized live testing, use a disposable VM or dedicated test installation.

---

## EICAR regression fixture

BIOAEGIS includes the standard EICAR anti-malware test signature as an inert local fixture.

The regression pipeline validates:

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

## Runtime and service hardening

Linux process telemetry continues to use `/proc` without killing processes or executing command lines.

For a controlled user-level deployment, the repository provides `service/bioaegis-user.service` with systemd hardening directives such as `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, and `MemoryDenyWriteExecute`.

This is user-service hardening, not a root privilege-separated endpoint daemon. A production deployment would require a dedicated service account, explicit privilege boundaries, lifecycle supervision, and stronger IPC authentication.

---

## Development / tests

Run locally:

```bash
bioaegis test
bioaegis redteam
```

GitHub Actions validates pytest plus CLI smoke tests for version, redteam, scan, audit, and monitor.

The current test suite covers **27 automated checks**, including confidence fusion, behavior clustering, local integrity signatures, archive inspection, specialist-provider contracts, sandbox manifests, and Linux near-real-time event monitoring.

---

## Project layout

```text
BIOAEGIS/
├── bioaegis/
│   ├── general_scanner.py      # Immune-memory lookup
│   ├── host_scanner.py         # Read-only filesystem scanner
│   ├── host_specialist.py      # Disposable deterministic specialist
│   ├── host_engine.py          # Detection / response lifecycle
│   ├── confidence.py           # Evidence fusion / confidence scoring
│   ├── behavior.py             # Deterministic behavior clustering
│   ├── archive_scanner.py      # Safe archive inspection
│   ├── integrity.py            # Local policy/memory integrity
│   ├── specialist_api.py       # Constrained specialist provider API
│   ├── sandbox.py              # Non-executing analysis workspace
│   ├── realtime.py             # Linux inotify event source
│   ├── quarantine.py            # Reversible isolation + restore
│   ├── runtime_scanner.py      # Linux process telemetry
│   ├── persistence_scanner.py  # User persistence telemetry
│   ├── network_scanner.py      # Listener inventory
│   ├── audit.py                # Unified defensive audit
│   ├── monitor.py              # Polling monitor
│   ├── redteam.py              # Inert red-team lab
│   ├── validator.py            # Response allow-list validator
│   └── memory.py               # Persistent immune memory
├── service/
│   └── bioaegis-user.service   # Hardened user-systemd template
├── tests/
│   ├── fixtures/               # Inert regression fixtures, including EICAR
│   ├── test_bioaegis.py        # Core regression suite
│   └── test_roadmap.py         # Research-baseline feature tests
├── memory/
│   └── countermeasures.json    # Stored validated responses
├── .github/workflows/
│   └── test.yml                # CI workflow
├── install.sh                  # User-local installer
└── requirements-dev.txt        # Development/test dependencies
```

---

## Roadmap status

### Research foundation — implemented baseline

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
- [x] Near-real-time Linux inotify event source
- [x] Deterministic confidence scoring and evidence fusion
- [x] Deterministic behavior clustering
- [x] Local integrity/signature primitive
- [x] Hardened user-systemd deployment template
- [x] Safe archive/container inspection baseline
- [x] Non-executing isolated analysis workspace
- [x] Constrained specialist-provider API
- [x] Inert red-team regression lab
- [x] EICAR regression fixture
- [x] Continuous integration

### Production-grade work still open

The research roadmap is implemented at baseline level, but these items remain necessary before claiming endpoint-product maturity:

- [ ] Hardware-backed or externally anchored policy signing
- [ ] Strong kernel / driver telemetry
- [ ] Complete memory forensics
- [ ] Production malware detonation sandbox with verified isolation
- [ ] Privilege-separated service with authenticated IPC
- [ ] Mature local ML model with adversarial evaluation
- [ ] Comprehensive container/archive format coverage
- [ ] Continuous adversarial benchmark corpus

---

## Security philosophy

> **Untrusted input never becomes an instruction.**

> **A specialist proposes; an independent validator decides.**

> **No validated cure is remembered before the defense is verified.**

> **When confidence is insufficient, BIOAEGIS should preserve evidence and escalate rather than guess.**

---

## License / status

BIOAEGIS is experimental security research software. Use it in controlled environments and do not treat its current implementation as equivalent to mature commercial endpoint-security products.
