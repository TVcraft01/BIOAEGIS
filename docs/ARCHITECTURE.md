# BIOAEGIS Architecture

BIOAEGIS is organized around a simple trust model: **observe first, investigate second, validate independently, then remember only verified responses**.

## Data flow

```text
              +----------------------+
              |      Host / Lab      |
              +----------+-----------+
                         |
             +-----------+-----------+
             |           |           |
             v           v           v
        File scan   Runtime scan  Persistence
             |           |           |
             +-----------+-----------+
                         |
                         v
                 Evidence / signals
                         |
                         v
                  General scanner
                         |
              +----------+----------+
              |                     |
           known                 unknown
              |                     |
              v                     v
        Reuse memory       Disposable specialist
                                    |
                                    v
                              Candidate action
                                    |
                                    v
                              Validator
                              /       \
                         reject       accept
                           |             |
                           v             v
                       No action     Quarantine
                                         |
                                         v
                                  Verify post-state
                                         |
                                         v
                                   Immune memory
                                         |
                                         v
                                 Fresh scan state
```

## Trust boundaries

### Scanners

Scanners are read-only telemetry and static-analysis components. They inspect content and metadata but do not execute scanned artifacts.

### Specialist

The specialist is disposable and constrained. Its output is a candidate response, not authority to modify the host.

### Validator

The validator is an independent allow-list boundary. A candidate that falls outside the declared response vocabulary is rejected.

### Quarantine

Quarantine is reversible containment. The implementation verifies file identity before isolation and after restoration using SHA-256.

### Immune memory

Memory stores validated defensive responses and matches behavioral triggers. Malformed memory is not trusted.

## Design principles

1. **Untrusted data stays data.** Scanner input never becomes an instruction stream.
2. **Specialists are disposable.** Learned or generated analysis must not become permanent authority.
3. **Validation is independent.** A proposed action must pass a separate policy boundary.
4. **Recovery is explicit.** Quarantine is reversible and hash-verified.
5. **Uncertainty is visible.** Heuristic detection is evidence, not proof.
6. **Fail closed.** Invalid memory and unsupported responses result in no autonomous action.

## Current boundaries

The repository provides a research baseline rather than a production endpoint-security stack. In particular, it does not claim kernel-level prevention, complete memory forensics, production malware detonation isolation, or protection against a fully privileged local attacker.
