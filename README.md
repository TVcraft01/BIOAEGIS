# BIOAEGIS

**BIOAEGIS** is a biological-inspired defensive system built around one idea:

> **When a new threat appears, create a temporary specialist to investigate it, keep only the validated countermeasure, then discard the specialist.**

## Current status

**v0.4.1 — defensive research prototype.**

BIOAEGIS currently provides read-only static file scanning, optional ClamAV deep scanning, reversible quarantine, behavior-based immune memory, a disposable specialist, an independent validator, Linux process telemetry, user persistence inspection, read-only listening-socket inventory, and a polling live monitor for controlled tests.

It is **not a production antivirus**. The specialist is still deterministic rather than a trained AI model, and the system does not provide guaranteed zero-day, kernel-level, memory-forensics, or complete network-intrusion detection.

## Install

```bash
curl -fsSL "https://raw.githubusercontent.com/TVcraft01/BIOAEGIS/main/install.sh?$(date +%s)" | bash
```

Then:

```bash
bioaegis --version
bioaegis test
```

The installer uses a user-local virtual environment, runs the test suite during installation, and does not require root privileges.

## File scanning

Detection only:

```bash
bioaegis scan ~/Downloads
```

Deep verification:

```bash
bioaegis scan ~/Downloads --deep
```

Real quarantine is explicit:

```bash
bioaegis scan ~/Downloads --quarantine
```

Quarantined files are moved, not deleted, to:

```text
~/.local/share/bioaegis/quarantine/
```

## Unified audit

BIOAEGIS can inspect four read-only layers at once:

```bash
bioaegis audit ~
bioaegis audit ~ --deep
```

The audit combines file/static findings, suspicious running-process command lines from `/proc`, common user persistence locations, and listening TCP/UDP sockets from `/proc/net`.

Normal home-directory scanning skips common cache/build trees to keep the audit responsive. Deep scanning remains available explicitly.

The audit never kills processes, closes sockets, deletes persistence entries, or modifies the host.

## Live monitor

For a controlled friend-led test, start the polling monitor in a disposable VM or dedicated test installation:

```bash
bioaegis monitor ~/Downloads --interval 2
```

For a single pass:

```bash
bioaegis monitor ~/Downloads --once
```

To enable the existing reversible quarantine response for newly detected file findings:

```bash
bioaegis monitor ~/Downloads --interval 2 --quarantine
```

When monitoring the home directory, file inspection is throttled while process, persistence, and network telemetry continue every cycle.

The monitor does not kill processes, alter persistence, or probe network ports.

## Red-team lab

Run the built-in defensive regression suite:

```bash
bioaegis redteam
```

The fixtures are inert: BIOAEGIS writes pattern examples, scans them without executing them, tests quarantine, and verifies behavior-based variant handling.

For an authorized friend-led test, use a disposable VM or dedicated test installation rather than the machine containing important data. The friend can use `audit` or `monitor` to see whether suspicious file content, persistence indicators, running-command indicators, or listening services become visible.

## Safety model

```text
                    HOST / TEST VM
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
      FILE SCAN       RUNTIME SCAN    PERSISTENCE SCAN
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                  GENERAL DETECTOR
                           │
                    unknown finding
                           │
                           ▼
                 DISPOSABLE SPECIALIST
                           │
                    candidate cure
                           │
                           ▼
                      VALIDATOR
                           │
                 accepted │ rejected
                           │       └──► no action
                           ▼
                      QUARANTINE
                           │
                      verify state
                           │
                           ▼
                     IMMUNE MEMORY
                           │
                           ▼
                 FRESH GENERAL SCANNER
                           │
                  specialist discarded
```

## Detection engines

The host scanner is deliberately conservative and read-only:

- bounded content sampling for normal scans;
- SHA-256 identity for actual findings;
- executable and hidden-executable signals;
- static signatures for several high-risk shell behaviors;
- text-oriented heuristics are not applied blindly to binary containers such as ISO images;
- optional ClamAV integration in deep mode;
- no execution of scanned files.

A heuristic signal is **not proof of malware**. Findings should be investigated, especially when an external signature engine is unavailable.

## Runtime telemetry

`bioaegis/runtime_scanner.py` reads Linux `/proc` process metadata and looks only for suspicious command-line indicators such as reverse-shell syntax, download-to-shell patterns, encoded command indicators, and execution from temporary locations.

It never sends signals to processes and never executes the captured command line.

## Persistence telemetry

`bioaegis/persistence_scanner.py` checks common user-level startup locations:

- `~/.config/autostart/`;
- `~/.config/systemd/user/`;
- `~/.profile`;
- `~/.bashrc`;
- `~/.zshrc`;
- `~/.config/fish/config.fish`.

It is read-only and only reports suspicious content.

## Network inventory

`bioaegis/network_scanner.py` reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6` to inventory listeners. It does not probe ports or connect to services.

## Immune memory

BIOAEGIS stores the validated response rather than the specialist. Behavioral triggers are used so that a known response can apply to a variant with matching behavior.

The real host lifecycle only commits a newly discovered countermeasure after the quarantine operation succeeds and the original path is confirmed absent while the quarantine copy exists.

## Development / tests

Use BIOAEGIS's installed interpreter so the private test dependencies are available:

```bash
bioaegis test
bioaegis redteam
```

Continuous integration runs the same tests on pushes and pull requests.

The test suite covers immune-memory learning and variant reuse, rejection of arbitrary commands, suspicious static behavior detection, binary false-positive resistance, reversible quarantine and verification, behavior variants with distinct hashes, persistence telemetry, `/proc` runtime parsing, and listener decoding.

## Architecture files

- `bioaegis/general_scanner.py` — persistent immune-memory lookup
- `bioaegis/host_scanner.py` — read-only filesystem scanner
- `bioaegis/host_specialist.py` — disposable host-finding specialist
- `bioaegis/host_engine.py` — detection → specialist → validation → quarantine → memory lifecycle
- `bioaegis/quarantine.py` — reversible user-local isolation
- `bioaegis/runtime_scanner.py` — read-only Linux process telemetry
- `bioaegis/persistence_scanner.py` — read-only user persistence telemetry
- `bioaegis/network_scanner.py` — read-only socket listener inventory
- `bioaegis/audit.py` — unified defensive audit
- `bioaegis/monitor.py` — polling live defensive telemetry
- `bioaegis/redteam.py` — inert local red-team regression lab
- `bioaegis/test_runner.py` — installed-environment test runner
- `bioaegis/validator.py` — independent allow-list validator
- `bioaegis/memory.py` — persistent validated countermeasure memory
- `bioaegis/lifecycle.py` — original simulation lifecycle
- `bioaegis/tui.py` — terminal research interface
- `tests/test_bioaegis.py` — regression suite

## Roadmap

### v0.4 — Defensive telemetry
- [x] Real read-only filesystem scanner
- [x] SHA-256 file identity
- [x] Optional ClamAV integration
- [x] Disposable host specialist
- [x] Independent action validator
- [x] Reversible quarantine
- [x] Quarantine verification
- [x] Immune-memory update after successful defense
- [x] Process telemetry
- [x] User persistence telemetry
- [x] Listening-socket inventory
- [x] Unified audit command
- [x] Polling live monitor
- [x] Red-team regression lab
- [x] Continuous integration

### Next
- [ ] Isolated malware-analysis sandbox
- [ ] Confidence scoring and evidence fusion
- [ ] Memory integrity protection
- [ ] Audit trail and rollback tooling
- [ ] Stronger behavioral clustering
- [ ] Pluggable local AI specialist
- [ ] Real-time filesystem/process monitoring
- [ ] Signed response policies
- [ ] Privilege-separated system service

## Important limitation

BIOAEGIS remains an experimental security project. It is suitable for controlled defensive research and testing, but it should not be represented as equivalent to mature endpoint-security products.
