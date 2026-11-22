# External Reference Research

Three read-only research agents reviewed primary documentation and public GitHub projects on 2026-11-21. They did not execute downloaded code or contact live infrastructure.

## Files

- `ubuntu-hardening.md`: Ubuntu 24.04, T-Pot isolation patterns, gVisor, nftables, auditd, Falco, unattended upgrades and Chainguard images.
- `honeypot-projects.md`: OpenAI/Ollama/vLLM impersonation, response timing, anti-fingerprinting, canaries and Shibboleth behavioral gates.
- `new-relic.md`: ingest-only credentials, Logs/Metric APIs, batching, gzip, backpressure, key rotation and NRQL alerts.

## Required application in this repository

1. Compare the deployment scripts and Compose configuration against the Ubuntu findings, especially Docker's firewall interaction, metadata-address blocking, DNS/NTP/New Relic-only egress and safe SSH disablement.
2. Compare persona responses against the honeypot findings. Use realistic bounded timing variation without making tests flaky. Do not copy stock banners or response rotation blindly; preserve deterministic test hooks.
3. Compare New Relic forwarding against the backpressure findings. Honor `Retry-After`, surface `NrIntegrationError` monitoring in operator docs, and retain bounded queues.
4. Cite the primary source URLs already present in these reports where their patterns are used.
5. Treat claims in these reports as leads until checked against the linked primary source. Do not add a dependency only because a reference project uses it.
