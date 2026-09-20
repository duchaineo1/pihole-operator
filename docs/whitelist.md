# Whitelist

Create a `Whitelist` resource to manage domain allow lists. It is automatically applied to all `Pihole` instances in the same namespace. Use this to override false positives from blocklists.

```yaml
apiVersion: pihole-operator.org/v1alpha1
kind: Whitelist
metadata:
  name: false-positives
spec:
  enabled: true
  domains:
    - "example.com"
    - "safe-site.org"
  description: "Known false positives"
```

## Spec fields

| Field | Default | Description |
|---|---|---|
| `domains` | (required) | List of domains to whitelist (1–1000) |
| `enabled` | `true` | Whether the whitelist is active |
| `description` | — | Human-readable description |
