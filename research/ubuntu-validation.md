# Ubuntu hardening validation

Follow-up validation of `ubuntu-hardening.md` against primary Docker, gVisor, Falco and Ubuntu documentation.

## Corrections

- Do not force DNS-over-TLS by default. Use pinned resolvers during bootstrap. DoT requires explicit `resolved.conf` SNI/configuration and `resolvectl` verification before port 53 can be restricted.
- No Watchtower, automatic image pulls, unverified tags or automatic/cron reboots. Pin reviewed image versions/digests and rebuild explicitly.
- Do not mount the Docker socket into the bait. Falco's least-privileged Modern eBPF mode still needs significant host capabilities; isolate it from the bait and document the residual privilege.
- Docker's iptables and experimental nftables backends differ. Do not assume `DOCKER-USER` exists under native nftables. Enforce container policy in a dedicated forward/egress path loaded before Docker and test from inside gVisor.
- gVisor netstack does not bypass the need for host packet filtering. No `--net-raw` runtime argument unless a measured requirement and separate security review justify it; it is not needed for the default bait.
- SSH disablement requires explicit `--apply --disable-ssh --console-confirmed`. Preserve provider-console recovery and firewall rollback.
- Keep `Automatic-Reboot "false"`; a cron reboot is still an automatic reboot and is not a loophole.
- Do not create extra rescue users unless the provider console requires one. A `DenyUsers` rule is not a substitute for testing console access.

## Required primary references

- Docker nftables: https://docs.docker.com/engine/network/firewall-nftables
- gVisor installation/runtime: https://gvisor.dev/docs/user_guide/install
- Falco least-privileged deployment: https://falco.org/docs/setup/container/#least-privileged-recommended
- Ubuntu `resolved.conf`: https://manpages.ubuntu.com/manpages/noble/man5/resolved.conf.5.html
- Ubuntu security updates: https://documentation.ubuntu.com/security/security-updates
- Docker socket risk: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet

Deployment tests must run from inside gVisor for metadata, denied internet, DNS/NTP and the exact New Relic `log-api`/`metric-api` endpoints. Host-only curl checks are insufficient.
