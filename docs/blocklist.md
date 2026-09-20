# Blocklist

Create a `Blocklist` resource to manage blocklists. It is automatically applied to all `Pihole` instances in the same namespace.

```yaml
apiVersion: pihole-operator.org/v1alpha1
kind: Blocklist
metadata:
  name: ads
spec:
  enabled: true
  sources:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  description: "Ad-blocking hosts"
  syncInterval: 1440
```

## Spec fields

| Field | Default | Description |
|---|---|---|
| `sources` | (required) | List of blocklist URLs (1–100) |
| `enabled` | `true` | Whether the blocklist is active |
| `syncInterval` | `1440` | Re-sync interval in minutes (60–10080) |
| `description` | — | Human-readable description |
| `targetNamespaces` | — | Namespaces to search for Pihole instances (see below) |

## Cross-namespace targeting

By default a `Blocklist` only targets `Pihole` instances in its own namespace.
Set `targetNamespaces` to reach Piholes in other namespaces:

| Value | Behaviour |
|---|---|
| _(omitted / empty)_ | Same namespace only (default, backward-compatible) |
| `["team-a", "team-b"]` | Only the listed namespaces |
| `["*"]` | All namespaces in the cluster |

```yaml
# Target specific namespaces
spec:
  sources:
    - https://example.com/malware.txt
  targetNamespaces:
    - team-a
    - team-b
```

```yaml
# Fleet-wide — every Pihole in the cluster
spec:
  sources:
    - https://example.com/malware.txt
  targetNamespaces:
    - "*"
```
