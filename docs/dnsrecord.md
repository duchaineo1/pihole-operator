# PiholeDNSRecord

Create a `PiholeDNSRecord` resource to manage local DNS records. Records are automatically applied to all `Pihole` instances in the same namespace.

Supported record types: `A`, `AAAA`, and `CNAME`.

```yaml
apiVersion: pihole-operator.org/v1alpha1
kind: PiholeDNSRecord
metadata:
  name: myhost-a-record
spec:
  hostname: myhost.home.local
  recordType: A
  ipAddress: "192.168.1.100"
  description: "A record for myhost"
```

```yaml
apiVersion: pihole-operator.org/v1alpha1
kind: PiholeDNSRecord
metadata:
  name: myhost-cname
spec:
  hostname: alias.home.local
  recordType: CNAME
  cnameTarget: myhost.home.local
  description: "CNAME alias pointing to myhost"
```

## Spec fields

| Field | Default | Description |
|---|---|---|
| `hostname` | (required) | DNS hostname (max 253 characters) |
| `recordType` | (required) | Record type: `A`, `AAAA`, or `CNAME` |
| `ipAddress` | — | IP address (required for `A` and `AAAA` records) |
| `cnameTarget` | — | Target hostname (required for `CNAME` records) |
| `description` | — | Human-readable description |
| `targetNamespaces` | — | Namespaces to search for Pihole instances (see below) |

## Cross-namespace targeting

By default a `PiholeDNSRecord` only targets `Pihole` instances in its own namespace.
Set `targetNamespaces` to push DNS records to Piholes in other namespaces — the same
semantics as `Blocklist`:

| Value | Behaviour |
|---|---|
| _(omitted / empty)_ | Same namespace only (default, backward-compatible) |
| `["team-a", "team-b"]` | Only the listed namespaces |
| `["*"]` | All namespaces in the cluster |

```yaml
# Apply to Piholes in team-a and team-b
spec:
  hostname: api.internal.example.com
  recordType: A
  ipAddress: "10.0.1.50"
  targetNamespaces:
    - team-a
    - team-b
```
