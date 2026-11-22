# Structure-aware scrubber re-review

Independent follow-up after commit `0506e0d`. Static source review only; no tests run by the reviewer.

## Closed

- Finding 1: exact marker validation rejects attacker-supplied `[redacted` prefixes.
- Finding 5: malformed `sk-local-` values no longer get the canary exemption.
- Finding 8: the responder's exact three-part `edge-*` JWT canary is preserved.
- Finding 10: fingerprint output is constrained to `hmac256:` plus 16 lowercase hex characters.

## Still open

1. **High:** credential-object schema exemption is a direct bypass. `{"password":{"type":"string","value":"hunter2"}}` preserves the secret because any object with a schema-like `type` is treated as a tool definition without context validation.
2. **High:** folded credentials still leak: `Authorization: Bearer\r\n  abc` leaves `abc`; `Cookie: a=b\r\n c=d` leaves `c=d`.
3. **High:** remaining name-grammar gaps include raw Unicode/confusables, `api key`, `user[password]`, and `cookies`.
4. **Medium:** standalone short alphabetic Bearer credentials such as `Bearer abc` and `Bearer token` survive; Authorization-line forms are covered.
5. **Medium:** network-path userinfo `//user:pa55@example.test/` and URI schemes longer than 32 characters survive.
6. **Medium:** `Cookie: session="hunter2"` leaks; `Set-Cookie` also over-redacts nonsecret attributes `Path=/`, `HttpOnly` and `Secure`.
7. **Medium:** `{"Authorization":"Bearer abc"}` fingerprints the whole `Bearer abc` value and drops the scheme, unlike header-line handling. Percent-encoded equivalents have different fingerprints; document or normalize that policy.
8. **New:** Digest authorization is partially scrubbed: `Authorization: Digest username="u", response="abc123"` leaves both values visible.
9. **New:** form/YAML boolean and null telemetry (`auth=true`, `token=null`) is destroyed inconsistently while equivalent JSON is preserved.

## Required triage

Fix the schema exemption, folded credentials, cookie quoting/attributes, standalone Bearer credentials, Digest handling and boolean/null preservation with exact-output tests. Handle network-path userinfo if Referer telemetry accepts it. Bound remaining Unicode/confusable and encoded-fingerprint normalization claims honestly in operator documentation rather than chasing every possible representation at the cost of telemetry.
