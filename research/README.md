# External Reference Research

Three read-only research agents reviewed primary documentation and public GitHub projects on 2026-11-21. They did not execute downloaded code or contact live infrastructure.

## Files

- `ubuntu-hardening.md`: Ubuntu 24.04, T-Pot isolation patterns, gVisor, nftables, auditd, Falco, unattended upgrades and Chainguard images.
- `honeypot-projects.md`: OpenAI/Ollama/vLLM impersonation, response timing, anti-fingerprinting, canaries and Shibboleth behavioral gates.
- `new-relic.md`: ingest-only credentials, Logs/Metric APIs, batching, gzip, backpressure, key rotation and NRQL alerts.
- `responder-review.md`: independent review of the first responder commit. Fix H1 Unicode bidirectional-mark normalization and H3 per-field declaration bounds before deployment; review the remaining findings.
- `telemetry-security.md`: independent security review of the first telemetry commit. Fix the High raw-credential leakage finding and all Medium findings before deployment; review Low findings.
- `server-review.md`: independent snapshot review, subsequently triaged by the host. Its slot-leak and missing-route claims were false; follow only the validated actions in `SECURITY_FIXES.md`.
- `protocol-review.md`: official-client contract mismatches in streaming usage, prompt arrays, Responses fields/cancellation, token embeddings and Ollama management responses. Fix all ten before claiming client compatibility.
- `main-review.md`: executable lifecycle review covering partial-listener cleanup, unsafe configuration bounds, secret-file permissions and healthcheck userinfo. Follow the validated fixes in `SECURITY_FIXES.md`.

## Required application in this repository

1. Compare the deployment scripts and Compose configuration against the Ubuntu findings, especially Docker's firewall interaction, metadata-address blocking, DNS/NTP/New Relic-only egress and safe SSH disablement.
2. Compare persona responses against the honeypot findings. Use realistic bounded timing variation without making tests flaky. Do not copy stock banners or response rotation blindly; preserve deterministic test hooks.
3. Compare New Relic forwarding against the backpressure findings. Honor `Retry-After`, surface `NrIntegrationError` monitoring in operator docs, and retain bounded queues.
4. Cite the primary source URLs already present in these reports where their patterns are used.
5. Treat claims in these reports as leads until checked against the linked primary source. Do not add a dependency only because a reference project uses it.
