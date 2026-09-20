# Examples

See the [`examples/`](https://github.com/duchaineo1/pihole-operator/tree/main/examples) directory for ready-to-use manifests:

- [`pihole.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/pihole.yaml) — minimal Pi-hole with annotated status output
- [`basic.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/basic.yaml) — minimal Pi-hole with defaults
- [`full.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/full.yaml) — all options configured
- [`pihole-loadbalancer.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/pihole-loadbalancer.yaml) — DNS and Web UI exposed via LoadBalancer with static IPs; demonstrates service drift detection
- [`existing-secret.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/existing-secret.yaml) — using a pre-existing Secret for the admin password
- [`resource-limits.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/resource-limits.yaml) — Pi-hole with CPU/memory requests and limits
- [`ingress.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/ingress.yaml) — Pi-hole with Ingress for web UI
- [`upstream-dns-ha.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/upstream-dns-ha.yaml) — custom upstream DNS with HA and PDB
- [`blocklist.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/blocklist.yaml) — ad-blocking blocklist
- [`cross-namespace-blocklist.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/cross-namespace-blocklist.yaml) — Blocklist targeting Piholes in other namespaces
- [`cross-namespace-dnsrecord.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/cross-namespace-dnsrecord.yaml) — PiholeDNSRecord targeting Piholes in other namespaces
- [`whitelist.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/whitelist.yaml) — domain allow list for false positives
- [`dnsrecord.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/examples/dnsrecord.yaml) — local DNS records (A and CNAME)

Apply an example:

```bash
kubectl apply -f examples/basic.yaml
```
