# pihole-operator

[![Unit Tests](https://github.com/duchaineo1/pihole-operator/actions/workflows/test.yml/badge.svg?branch=main&event=push)](https://github.com/duchaineo1/pihole-operator/actions/workflows/test.yml)
[![E2E Tests](https://github.com/duchaineo1/pihole-operator/actions/workflows/e2e.yml/badge.svg?branch=main&event=push)](https://github.com/duchaineo1/pihole-operator/actions/workflows/e2e.yml)
[![Security Scan](https://github.com/duchaineo1/pihole-operator/actions/workflows/security-scan.yml/badge.svg?branch=main)](https://github.com/duchaineo1/pihole-operator/actions/workflows/security-scan.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A Kubernetes operator to declaratively deploy and configure [Pi-hole](https://pi-hole.net/).

- **Deploy** Pi-hole from a single `Pihole` resource, with optional HA (per-pod storage, PodDisruptionBudget)
- **Configure** blocklists, whitelists and local DNS records as Kubernetes resources, synced to every replica
- **Target** Pi-hole instances across namespaces

## Quick start

```bash
helm install pihole-operator oci://ghcr.io/duchaineo1/pihole-operator/charts/pihole-operator \
  --namespace pihole-operator --create-namespace

kubectl apply -f - <<'YAML'
apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: my-pihole
spec:
  size: 1
YAML
```

## Documentation

Full docs: **https://duchaineo1.github.io/pihole-operator/**

- [Getting started](docs/getting-started.md)
- Resources: [Pihole](docs/pihole.md), [Blocklist](docs/blocklist.md), [Whitelist](docs/whitelist.md), [PiholeDNSRecord](docs/dnsrecord.md)
- [Design](docs/design.md): architecture and decisions
- [Examples](examples/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `make help` for available targets.

## License

Apache License 2.0. See [LICENSE](LICENSE).
