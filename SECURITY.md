# Security Policy

## Scope

BIOAEGIS is experimental defensive security research software. Reports about vulnerabilities in the scanner, quarantine logic, validator, memory handling, CLI, service template, or analysis boundaries are welcome.

## Reporting a vulnerability

Please do not publish an exploitable vulnerability with working attack instructions before it has been reviewed.

Open a private security report through the repository's GitHub security features when available. If private reporting is unavailable, open a minimal issue containing:

- affected version or commit;
- affected component;
- security impact;
- safe reproduction steps;
- relevant logs or test output with secrets removed.

Do not include passwords, private keys, tokens, personal data, or live malware samples in an issue.

## Research boundaries

BIOAEGIS intentionally avoids executing untrusted artifacts and does not provide a live malware detonation environment. Live malware testing should be isolated from production systems and performed in an appropriately hardened lab environment.

## Supported versions

| Version | Status |
| --- | --- |
| `main` | Supported for security research |
| Older releases | Best effort |
