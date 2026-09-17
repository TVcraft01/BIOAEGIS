# BIOAEGIS architecture and trust model

BIOAEGIS is a Linux-oriented defensive research platform. Its architecture is intentionally layered so that detection, investigation, policy validation, containment, memory, and UI are not the same trust boundary.

## Runtime topology

```text
                    USER SESSION
                        │
              ┌─────────┴─────────┐
              │                   │
              ▼                   ▼
       PROTECTION SERVICE      SECURITY CONSOLE
        systemd --user         QtWebEngine / local HTTP
              │                   │
      ┌───────┼────────┐          │
      │       │        │          │
   inotify  /proc  persistence    ├── health
      │       │        │          ├── memory
      └───────┼────────┘          ├── quarantine
              ▼                   └── scan POST
       evidence collection
              │
              ▼
       behavioral scoring
              │
       known / unknown behavior
          │             │
          ▼             ▼
    signed memory    specialist
                         │
                         ▼
                  candidate response
                         │
                         ▼
                    Validator
                    │       │
                 reject    accept
                    │       │
                    ▼       ▼
                 no-op   confidence gate
                              │
                         HIGH only for
                      automatic containment
                              │
                              ▼
                         quarantine
                              │
                         hash verify
                              │
                         memory update
```

## Trust boundaries

### 1. Scanner boundary

Host scanners are read-only. They inspect file content, metadata, archive members, process metadata, persistence locations, and listener tables. They do not execute scanned artifacts or use arbitrary shell commands.

### 2. Specialist boundary

A specialist receives a finding and returns a structured proposal. It is not given arbitrary command execution authority. Its output is treated as untrusted until passed through the validator.

### 3. Validator boundary

The validator applies an explicit action allow-list and recovery requirements. A candidate that requests unsupported behavior is rejected.

### 4. Automatic-action boundary

Manual quarantine requests and automatic containment are intentionally different. Continuous protection requires the evidence fusion result to be `HIGH` before automatic quarantine is attempted. This is designed to reduce false positives at the cost of allowing some medium-confidence findings to remain for review.

### 5. Quarantine boundary

Quarantine moves a file into controlled storage, records the original path and SHA-256, and verifies the resulting state. Restoration checks the stored hash and refuses to overwrite an existing destination.

### 6. Memory boundary

Validated countermeasures are serialized as JSON and HMAC-signed. A missing, malformed, or tampered signature causes memory loading to fail closed.

The HMAC key is stored under `~/.config/bioaegis/`, outside the replaceable application directory. This provides persistence across application upgrades, but it is not a hardware-backed trust root and does not defend against a privileged attacker who can replace the key.

### 7. Installation-integrity boundary

The installed venv package, critical deployment assets, service units, and package metadata are recorded in `.integrity-manifest.json`. The manifest is HMAC-signed and periodically rechecked by the protection service.

A mismatch changes the protection health state to `degraded`; it does not pretend that the endpoint is healthy.

### 8. Update boundary

The update verifier expects an Ed25519-signed release manifest and independently checks the artifact SHA-256. An invalid, unsigned, oversized, or malformed update is rejected.

The repository currently ships the verifier and scheduler, but the manifest is intentionally disabled until a release-signing workflow is configured with the matching private key. This prevents the project from pretending that an unsigned update path is secure.

## Failure behavior

| Failure | Result |
| --- | --- |
| malformed memory | memory ignored |
| invalid response action | candidate rejected |
| medium-confidence automatic finding | no automatic quarantine |
| quarantine verification failure | action reported as failed |
| inotify queue overflow | periodic full sweep |
| installation-integrity mismatch | health becomes `degraded` |
| update signature mismatch | update rejected |
| update SHA-256 mismatch | update rejected |
| unavailable update manifest | no update |
| missing native GUI backend | browser fallback |

## Security limitations

BIOAEGIS does not yet provide a privileged, independently trusted reference monitor. In particular:

- a fully privileged attacker can interfere with a user-level service;
- local HMAC integrity protects against accidental or ordinary tampering, not a privileged attacker with access to the trust material;
- inotify is an event source, not a security boundary;
- runtime, persistence, and network telemetry are currently read-only observation;
- the analysis sandbox is not a production malware detonation environment;
- detection performance, false-positive rates, and malware efficacy have not been independently established.

The architecture is deliberately explicit about these limitations so later engineering work can target measurable gaps rather than hidden assumptions.
