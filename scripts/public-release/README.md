# Public Release Kit

Deploy a verified release to the public HTTPS gateway.

## Prerequisites

- Release-check passed: `COMMIT=<full-sha> PLATFORM=linux/amd64 bash scripts/public-release-check.sh authorize`
- Package created: `COMMIT=<full-sha> PLATFORM=linux/amd64 bash scripts/public-release-check.sh package`
- DNS name set: `export ATTACKBOX_PUBLIC_NAME=<dns-name>`
- SSH config has `attackbox` alias with IP address
- Previous release directory exists

## Commands

### Prepare release

```bash
bash scripts/public-release/prepare.sh COMMIT PREVIOUS_RELEASE_DIR
```

Creates `~/.local/share/attackbox-public-releases/COMMIT/` with bundle, source, and cutover scripts.

### Deploy

```bash
cd ~/.local/share/attackbox-public-releases/COMMIT
./cutover.sh
```

Sequence:
1. Verify previous release is live
2. Close previous release ingress
3. Roll back previous release on host
4. Stage new release (closed)
5. Verify staged deployment
6. Open ingress
7. Verify public access

### Rollback

```bash
cd ~/.local/share/attackbox-public-releases/PREVIOUS_COMMIT
./firewall.sh verify-open  # confirm it is open
```

If a newer release is already live, roll back:

```bash
cd ~/.local/share/attackbox-public-releases/NEWER_COMMIT
./firewall.sh close
cd ~/.local/share/attackbox-public-releases/PREVIOUS_COMMIT
./firewall.sh open BUNDLE_SHA
```

Replace `BUNDLE_SHA` with the value from that release's `bundle.sha256` file.

## Example

Release cfba7a0 to e123d9b:

```bash
export ATTACKBOX_PUBLIC_NAME=<public-dns-name>
COMMIT=e123d9b0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 PLATFORM=linux/amd64 \
  bash scripts/public-release-check.sh check
COMMIT=e123d9b0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 PLATFORM=linux/amd64 \
  bash scripts/public-release-check.sh authorize
COMMIT=e123d9b0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 PLATFORM=linux/amd64 \
  bash scripts/public-release-check.sh package
bash scripts/public-release/prepare.sh \
  e123d9b0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 \
  ~/.local/share/attackbox-public-releases/cfba7a059799436bc3a22f85a55a77ff2bb59cd7
cd ~/.local/share/attackbox-public-releases/e123d9b0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
./cutover.sh
```
