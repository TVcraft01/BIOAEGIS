# BIOAEGIS release and update signing

The automatic updater is intentionally fail-closed. A maintainer must configure the release-signing secret before publishing a signed update.

## One-time signing setup

1. Generate a dedicated Ed25519 release keypair outside the repository.
2. Store the private key in the GitHub repository Actions secret named `BIOAEGIS_UPDATE_PRIVATE_KEY`.
3. Replace `bioaegis/trusted_update_key.pem` with the matching public key and commit it.
4. Keep the private key out of the repository, local installer, CI logs, and release artifacts.
5. Publish a test tag only after the public/private key pair has been verified.

The release workflow refuses to publish an enabled manifest if the private key does not derive the exact public key pinned in the repository.

## Release

Create and push a version tag matching `bioaegis/__init__.py` and `pyproject.toml`, for example:

```text
v0.7.0
```

The workflow then builds the wheel, verifies that the wheel contains the trust anchor, creates the GitHub release, computes the SHA-256 digest, signs the canonical manifest with Ed25519, and publishes the signed manifest to `main`.

## Rotation

When rotating the update key:

1. generate a new keypair;
2. update `bioaegis/trusted_update_key.pem`;
3. store the matching private key in `BIOAEGIS_UPDATE_PRIVATE_KEY`;
4. verify CI and the release workflow before enabling updates again.

Key rotation requires a new trusted repository state. It cannot be safely performed by an unsigned automatic update.
