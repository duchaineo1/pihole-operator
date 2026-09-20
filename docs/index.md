# pihole-operator

A Kubernetes operator that deploys [Pi-hole](https://pi-hole.net/) and keeps its configuration declarative.

Instead of clicking through the Pi-hole UI, describe what you want as Kubernetes resources and let the operator make it so, on every replica.

| Resource | What it manages |
|---|---|
| [`Pihole`](pihole.md) | A Pi-hole deployment: StatefulSet, Services, storage, admin password, ingress, TLS, upstream DNS, HA |
| [`Blocklist`](blocklist.md) | Ad-blocking lists, pushed to every Pi-hole pod |
| [`Whitelist`](whitelist.md) | Allow-listed domains (false positives) |
| [`PiholeDNSRecord`](dnsrecord.md) | Local `A`, `AAAA` and `CNAME` records |

## Where to go next

- **[Getting started](getting-started.md)**: install the operator and create your first Pi-hole.
- **[Design](design.md)**: how the operator is built and why.
- **[Examples](examples.md)**: ready-to-apply manifests.
