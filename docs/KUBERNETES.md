# AttackBox on a single-node K3s VPS

**Recommendation:** Run the passive Go simulator and nginx together in one sandboxed Pod. Keep Compose as the rollback target. K3s gives this project repeatable releases, not more capacity on the same VPS. If throughput alone drives the decision, benchmark Compose first.

This is a design, not an installation runbook. It does not assume that the VPS already runs K3s. It does not authorize a deployment, public ingress, remote telemetry, or a traffic test against the VPS.

## What “k0ps-aligned” means here

This repository does not define `k0ps`. This plan interprets it as the [kOps](https://kops.sigs.k8s.io/) operating model: declare desired state, pin versions, review a diff, approve the change, and rehearse recovery. **K3s owns the cluster.** Do not run kOps against it. If the intended reference was [k0s](https://docs.k0sproject.io/head/install/), that is an alternative Kubernetes distribution, not an add-on for K3s.

## What moves, and what does not

The [Ubuntu profile](../compose.yaml) runs two containers. nginx publishes TLS on host loopback `8443` and an HTTP redirect on `8080`. Only the OpenAI persona is enabled. The [gVisor override](../compose.gvisor.yaml) selects `runsc` for both containers. The host owns the shipper, its queue, and the firewall.

| Boundary | Single-node design |
|---|---|
| Application image | Use passive revision `b3504b8ac6` as the baseline. Build for the node architecture from passive source only. Reuse the [non-root image pattern](../Dockerfile). Pin the resulting OCI digest in the Deployment. A local Docker image ID does not identify the image in a registry or in K3s containerd. |
| Request path | Use one Deployment. Each Pod runs nginx on `8443` and the Go binary on `127.0.0.1:8080`. A `ClusterIP` Service selects **nginx**, not the Go port. Pod containers share loopback. A Service cannot reach a loopback-only listener directly. |
| Other personas | Start with OpenAI. To add vLLM or Ollama, assign a distinct Pod-loopback port to each enabled listener. Route by TLS hostname at nginx so compatible `/v1` routes do not collide. No additional public port is necessary. |
| TLS and streams | Terminate TLS only at nginx. Mount the TLS Secret only there. Replace the [Compose upstream](../docker/nginx/nginx.conf) with Pod loopback. Keep response buffering, caching, and compression off for SSE and NDJSON. Bound headers, request bodies, timeouts, and temporary storage. |
| Observations | Use only the passive JSONL fields: `time`, `persona`, `method`, `route`, `status`, `response_bytes`. Disable nginx access logs. Keep request-bearing errors out of container logs. The Compose log format includes the request line, client address, and headers. Do not copy it. |
| Host state | The passive Pod needs no PVC, host mount, collector key, or external connection. Rotate CRI logs on the node. Reserve disk for K3s and the OS. A Docker journal reader does not automatically follow containerd logs. |

**Private deployment parity is a separate gate.** Compose sets `ATTACKBOX_FULL_EVIDENCE=true`. Disabling it does not produce the six-field passive contract. Private sessions also do not transfer between replicas. If private observations are required, a passive rollout cannot replace Compose.

- Keep the systemd shipper, disk queue, Falco and journal readers, and evidence collection on the host. Passive stdout is not the shipper's wire protocol.
- For private bait only, review an exception for a read-only directory mount containing `/run/attackbox/spool.sock`. Do not expose Docker, containerd, the queue, or host credentials. Prove that `runsc` permits the intended socket and that `SO_PEERCRED` reports UID `65532`. Test rejection on the other role sockets and reconnection after shipper restart.
- The bait endpoint shares four connections and a 1 MiB/s budget across producers. Replicas do not multiply that budget. Measure queue growth, drops, disk space, and recovery with a local test sink. A socket write proves neither disk commit nor remote delivery. See the [trust boundaries](architecture.md) and [operator gates](operator.md).
## Conversion work

1. **Inventory the node before selecting a release.** Record CPU architecture and steal time, allocatable memory, SSD space and latency, NIC limits, and console recovery. For existing K3s, also record the version, datastore, CNI, runtime handlers, listeners, and workloads. Rehearse on an isolated equivalent node first. Do not disable another workload’s ingress or change its datastore.
2. **Declare the node and workload separately.** Put the proposed workload under `deploy/k3s/` in the private repository. Use built-in Kustomize: Namespace, RuntimeClass, Deployment, Service, nginx ConfigMap, and NetworkPolicy. Keep the pinned [K3s configuration](https://docs.k3s.io/installation/configuration), runtime template, and firewall policy outside the application manifest. Record source revision, image digests, and manifest revision together. Keep Secret values and kubeconfigs out of Git. The existing `make deploy` targets Compose, not Kubernetes.
3. **Make the sandbox mandatory.** Install pinned `runsc` and `containerd-shim-runsc-v1` on the rehearsal node. Extend the [K3s containerd base template](https://docs.k3s.io/advanced#configuring-containerd) for the installed containerd version. Docker runtime registration does not carry over. Use `runtimeClassName: gvisor` with [handler `runsc`](https://gvisor.dev/docs/user_guide/containerd/quick_start/). Require evidence from a running sandbox. A missing handler must stop rollout, not fall back to `runc`.
4. **Constrain the Pod.** Enforce restricted Pod Security for the passive namespace. Run both containers as non-root with read-only roots, no privilege escalation, `seccompProfile: RuntimeDefault`, and all capabilities dropped. Disable service-account token mounts. Disallow host networking, host PID, and host paths. Size writable nginx paths with bounded `emptyDir` volumes. Set CPU, memory, and ephemeral-storage requests and limits. Reserve node resources for the OS, kubelet, and K3s.
5. **Keep the data plane private.** On a dedicated rehearsal cluster, disable bundled Traefik and ServiceLB before startup. Their [defaults](https://docs.k3s.io/networking/networking-services) can claim host ports 80 and 443. Start with `ClusterIP` only. For an approved private traffic test, use ServiceLB alone for TLS `443` → nginx `8443`. Restrict access to the generator’s private address. Review all LoadBalancer Services before enabling the controller. Block NodePort bypass at the provider and host. A loopback port-forward is useful for smoke tests, not for capacity measurements.
6. **Rebuild the network rules for K3s.** Default-deny Pod ingress and egress. Admit only the intended TLS path. The passive Pod needs no DNS. Retain an enforcing network-policy controller. [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) alone does not isolate a Pod from its node. The [host rules](../deploy/nftables/attackbox.nft) match Docker bridges. Account for CNI interfaces, routes, and service NAT without flushing K3s rules. Keep the API server (`6443`), kubelet (`10250`), and overlay ports off the public network. Use a private admin path, least-privilege RBAC, and encryption at rest for Secrets.

## What sets the traffic ceiling

Each passive persona admits **256 concurrent handlers, but only 8 per TCP peer**. nginx connects from loopback, so all clients share eight slots per persona per Pod. The CLI does not expose these limits. More CPU does not change them.

Before a high-traffic rollout, prove source preservation through the load balancer. Enforce per-client and total limits at nginx using the verified peer. Discard untrusted forwarding headers. In a new application revision, give the trusted loopback upstream an explicit, bounded Go concurrency budget. Keep standalone defaults unchanged. Also measure the serialized stdout writer: slow log storage can stall handlers even with spare CPU.

Size for **time in flight**, not only requests per second. For example, 20 new streams/s occupying a handler for 15 seconds need about **300 simultaneous handlers**. Idle keep-alive connections consume sockets, not handler slots. Measure TLS handshakes, file descriptors, and upstream connections as well as request rate.

| Qualification step | Evidence to record |
|---|---|
| Define the target | Agree on short requests/s, new streams/s, concurrent streams, payload sizes, p99 latency, time to first event, and acceptable loss. Record the VPS shape and link rate. The operator guide’s 4-vCPU / 8-GB host is a starting estimate, not a K3s result. |
| Compare like with like | Use the same passive revision, nginx policy, `runsc`, and VPS shape for Compose and K3s. Use an authorized private generator and synthetic inputs. Include model discovery, short JSON, SSE, NDJSON, slow readers, and disconnects. Do not benchmark through the API server. The [Go microbenchmarks](../scripts/run-benchmarks.sh) do not measure this path. |
| Find the sustainable rate | Increase offered load in steps. Record offered, admitted, and completed requests/s, p95/p99 latency, first-event time, incomplete streams, `429`, and unexpected `5xx`. Watch CPU throttling and steal, RSS, disk latency, log bytes/s, NIC saturation, and open sockets. |
| Accept or reject | As a proposed gate, sustain the agreed mix for 60 minutes with at least 25% CPU and memory headroom. Require the latency and loss budgets to hold, no OOM kills or restarts, and no unexplained missing observations. Beyond the target, require bounded `429` responses and recovery after load subsides. |

Start with one replica. If the scheduler and node have room for two, compare completions and tail latency. An HPA cannot add CPU, disk bandwidth, or network capacity to one machine. If the NIC saturates first, move traffic filtering upstream. If service must survive node loss, use another failure domain.

## Promotion and rollback

1. **Render and review.** Once manifests exist, run `kubectl kustomize deploy/k3s/` locally. Use server-side dry-run and `kubectl diff` only against the approved rehearsal context. Reject mutable images, public listeners in the closed profile, unexpected egress, or rendered credentials. Repeat the diff after upgrades to detect drift.
2. **Prove function and containment.** Fetch `/v1/models` through nginx with certificate validation. Check fixed JSON and stream framing for every enabled persona. A green `/nginx-health` proves only that nginx answered. Use a synthetic marker to check that no body, header, query, or client identifier reaches logs. Establish a working positive control before interpreting a denial. Prove denial of internet, metadata, DNS, node management, and other workload access for IPv4 and IPv6 where enabled.
3. **Test a release under load.** Use separate readiness and liveness checks. Remove the old Pod from endpoints before stopping nginx or bait. Measure active-stream completion during replacement. The passive binary allows five seconds for shutdown. A longer `terminationGracePeriodSeconds` alone cannot extend that deadline. Budget a surge Pod or declare a maintenance window.
4. **Restore before cutover.** On a new single server, use the default [SQLite datastore](https://docs.k3s.io/datastore). Take a consistent backup of `/var/lib/rancher/k3s/server/db/` and the matching `/var/lib/rancher/k3s/server/token`. Encrypt the off-node copy. Keep the node configuration, firewall, and TLS recovery material separately. Rehearse [restore](https://docs.k3s.io/datastore/backup-restore) on a disposable node. SQLite backups do not include host queues or CRI logs. Record recovery time and the data-loss window.
5. **Switch only with separate approval.** Keep the previous image digests, manifest revision, and Compose release available. For an application regression, restore the previous manifest and digests. For a sandbox, network, or capacity failure, close the new route first. Hand the listener back to Compose only after K3s releases it. Never run two writers on the same host queue. Repeat the private TLS and containment checks before considering public access.

**Go/no-go:** If K3s misses the traffic target or weakens containment or privacy, keep Compose. Multiple Pods can cover a process restart. They cannot cover loss of the VPS.
