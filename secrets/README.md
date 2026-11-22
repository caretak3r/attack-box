# Secrets Directory

This directory holds sensitive files required for AttackBox deployment. **Never commit actual secrets to git.**

## Required Files

### `redaction.key`
Redaction secret for session/embedding keys (32+ bytes).

**Generate**:
```bash
head -c 64 /dev/urandom | base64 -w 0 > secrets/redaction.key
chmod 600 secrets/redaction.key
```

### `server.crt`
TLS certificate for nginx proxy.

**Generate (self-signed, development only)**:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout secrets/server.key \
  -out secrets/server.crt \
  -subj "/CN=attackbox.local"
chmod 644 secrets/server.crt
```

**Production**: Use a CA-signed certificate.

### `server.key`
TLS private key for nginx proxy.

**Generated alongside `server.crt`**:
```bash
chmod 600 secrets/server.key
```

## Security

- All files in this directory are gitignored
- Keep file permissions tight: 600 for keys, 644 for certs
- Rotate secrets before production deployment
- Never log, echo, or transmit secret contents
- For production, use a proper secret management system (HashiCorp Vault, AWS Secrets Manager, etc.)

## Verification

```bash
# Check redaction key (should be 32+ bytes)
wc -c < secrets/redaction.key

# Verify TLS certificate
openssl x509 -in secrets/server.crt -text -noout

# Verify TLS key
openssl rsa -in secrets/server.key -check
```
