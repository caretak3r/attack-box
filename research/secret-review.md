# Secret scrubber security audit

Source: independent `SecretScrubberReview` agent, static review only. The host separately ran the package tests.

## Observed test evidence

- Initial `go test -race ./internal/secret` failed on `Authorization: Bearer abc`, `?access_token=qq9&x=1`, and `Authorization: Basic dXNlcjpwYXNz`.
- After worker changes, the same command passed (`ok attackbox/internal/secret 1.119s`). The remaining findings below still require triage; do not treat that pass as proof of complete coverage.

## Priority findings to fix or explicitly bound

1. **Marker-prefix bypass:** values beginning `[redacted` are trusted. `{"password":"[redacted]hunter2"}` and `access_token=[redacted]qq9` can leak the suffix. Idempotence must recognize only complete validated markers.
2. **Field-name bypasses:** camelCase (`accessToken`, `clientSecret`, `refreshToken`), escaped JSON names and encoded form names need credential-name canonicalization without normalizing nonsecret payload bytes.
3. **JSON structure:** numeric, array and object-valued credential fields can leak and regex replacement can corrupt valid JSON. Prefer structure-aware span handling; preserve all nonsecret siblings byte-for-byte.
4. **Quoted/multiline values:** quoted env/YAML credentials and block private keys need a defined policy. Do not damage subsequent nonsecret lines.
5. **Canary bypasses:** any `sk-local-` prefix is currently allowed in one path; only exact decoy-generated shapes may survive. Preserve every genuine canary, including JWT-like and cookie-carried forms.
6. **Cookie idempotence:** cookie replacement must preserve valid canaries and must not fingerprint its own marker on a second scrub.
7. **Fingerprint contract:** fingerprints must use a bounded nonreversible grammar such as `hmac256:<hex>`; never allow callback output to re-emit secrets or corrupt JSON. Equivalent credentials should have a documented correlation policy.
8. **Authorization heuristics:** test short/conventional bearer values, empty-username Basic credentials and benign prose such as `bearer bonds` to avoid both leaks and telemetry destruction.
9. **URL userinfo:** empty usernames and long passwords must not bypass redaction; preserve host/path and noncredential query fields.

## Telemetry-preservation requirements

Add exact-output tests for realistic tool schemas (`argv`, `cwd`, `parallel_tool_calls`), `metadata.client`, `identification-declined`, noncredential URL queries, Unicode nonces, output-window markers and every valid canary shape. Valid JSON nonsecret keys, ordering, whitespace, escapes and sibling values must survive. Fuzzing must include redaction and canary-preservation oracles, not idempotence alone.

Do not claim that arbitrary free-text secret detection is perfect. Use dedicated New Relic isolation as the remaining blast-radius control and document the supported redaction shapes honestly.
