# pihole-operator

A Kubernetes operator to declaratively deploy and configure Pi-hole instances.

## Features

- Deploy Pi-hole with a single custom resource
- Manage blocklists declaratively
- Whitelist management
- DNS record management (A, AAAA, CNAME)
- Custom upstream DNS servers
- High availability with automatic PodDisruptionBudget
- Ingress support for the web UI

## Installation

```bash
helm install pihole-operator oci://ghcr.io/duchaineo1/pihole-operator/charts/pihole-operator \
  --version v1.0.9 \
  --namespace pihole-operator --create-namespace \
  -f dist/chart/values.yaml
```

## Custom Resources

### Pihole

Create a `Pihole` resource to deploy a Pi-hole instance:

```yaml
apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: my-pihole
spec:
  size: 1
  timezone: "America/New_York"
```

The operator creates a Deployment, Services (DNS + Web), a PVC, and a Secret containing the admin password.

#### Spec fields

| Field | Default | Description |
|---|---|---|
| `size` | `1` | Number of replicas |
| `adminPassword` | random | Password for the web UI. Omit to auto-generate. |
| `adminPasswordSecretRef` | — | Reference to an existing Secret (see below) |
| `timezone` | `UTC` | Timezone (e.g. `America/New_York`) |
| `storageSize` | `1Gi` | PVC size for Pi-hole data |
| `storageClass` | cluster default | Storage class for the PVC |
| `dnsServiceType` | `NodePort` | Service type for DNS (`ClusterIP`, `NodePort`, `LoadBalancer`) |
| `webServiceType` | `ClusterIP` | Service type for the web UI |
| `dnsLoadBalancerIP` | — | Static IP for DNS LoadBalancer |
| `webLoadBalancerIP` | — | Static IP for Web LoadBalancer |

> **Service drift detection:** If you change `dnsServiceType`, `webServiceType`, `dnsLoadBalancerIP`, or `webLoadBalancerIP` after the Pihole resource is created, the operator automatically detects the difference and updates the existing Service on the next reconcile. No manual deletion of the Service is required.
| `image` | `docker.io/pihole/pihole:2025.11.0` | Container image |
| `resources` | — | CPU/memory requests and limits (standard Kubernetes resource requirements) |
| `upstreamDNS` | Pi-hole defaults | List of upstream DNS servers (e.g. `["1.1.1.1", "9.9.9.9"]`) |
| `ingress` | — | Ingress configuration for the web UI (see below) |
| `tls` | — | TLS verification settings for Pi-hole API communication (see below) |
| `serverTLS` | — | TLS certificate for Pi-hole's own HTTPS endpoint (see below) |

#### Status fields

After each reconcile the operator populates the following fields on `status`:

| Field | Description |
|---|---|
| `conditions` | Standard Kubernetes conditions (e.g. `Available`) |
| `adminPasswordSecret` | Name of the Secret containing the admin password |
| `serviceName` | Name of the main service |
| `readyReplicas` | Number of ready StatefulSet replicas |
| `dnsIP` | IP of the DNS service (LoadBalancer ingress IP, or ClusterIP for NodePort/ClusterIP types) |
| `webURL` | URL to the Pi-hole web interface, e.g. `http://10.96.0.80/admin` |
| `queriesTotal` | Total DNS queries processed (polled from pod 0) |
| `queriesBlocked` | DNS queries blocked by Pi-hole (polled from pod 0) |
| `blockPercentage` | Percentage of queries blocked, e.g. `"9.99%"` (polled from pod 0) |
| `gravityDomains` | Number of domains in the gravity blocklist database (polled from pod 0) |
| `uniqueClients` | Unique clients seen by Pi-hole (polled from pod 0) |
| `statsLastUpdated` | RFC 3339 timestamp of the last successful stats fetch |

Stats fields are populated on a best-effort basis — if the Pi-hole API is unreachable (e.g. during initial startup), the reconcile succeeds anyway and stats will be retried on the next reconcile cycle (every minute by default).

Use `kubectl get pihole -o wide` or `kubectl get pihole -A` to see DNS IP and extended columns:

```bash
kubectl get pihole my-pihole -o wide
# NAME         READY   DNS IP         WEB URL                      QUERIES   BLOCKED   GRAVITY
# my-pihole    1/1     10.96.0.53     http://10.96.0.53/admin      48291     9.78%     150283
```

#### Admin password

There are three ways to configure the admin password:

**Auto-generated (default)** — omit both `adminPassword` and `adminPasswordSecretRef`. The operator creates a Secret named `<pihole-name>-admin` with a random 16-character password.

```yaml
spec: {}
```

Retrieve it with:

```bash
kubectl get secret my-pihole-admin -o jsonpath='{.data.password}' | base64 -d
```

**Inline password** — set `adminPassword` directly. The operator creates the Secret for you.

```yaml
spec:
  adminPassword: "my-password"
```

**Existing Secret** — set `adminPasswordSecretRef` to reference a Secret you manage yourself. The operator will not create or modify the Secret.

```yaml
spec:
  adminPasswordSecretRef:
    name: my-pihole-secret
    key: password          # optional, defaults to "password"
```

When `adminPasswordSecretRef` is set, `adminPassword` is ignored.

#### Resource limits

Set CPU and memory requests/limits for the Pi-hole container:

```yaml
spec:
  resources:
    requests:
      cpu: "100m"
      memory: "128Mi"
    limits:
      cpu: "500m"
      memory: "512Mi"
```

#### Upstream DNS

Override Pi-hole's default upstream DNS servers:

```yaml
spec:
  upstreamDNS:
    - "1.1.1.1"
    - "1.0.0.1"
    - "9.9.9.9"
```

#### High availability

When `size` is greater than 1, each instance gets its own PVC and the operator syncs blocklists and DNS records to every pod individually. A PodDisruptionBudget is automatically created with `minAvailable: 1` to ensure at least one Pi-hole pod survives voluntary disruptions.

```yaml
spec:
  size: 3
```

#### Ingress

Expose the Pi-hole web UI via a Kubernetes Ingress resource:

```yaml
spec:
  ingress:
    enabled: true
    host: pihole.example.com
    ingressClassName: nginx
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "0"
    tls:
      enabled: true
      secretName: pihole-tls
```

| Field | Default | Description |
|---|---|---|
| `ingress.enabled` | `false` | Whether to create an Ingress |
| `ingress.host` | (required) | Hostname for the Ingress rule |
| `ingress.ingressClassName` | — | Ingress class to use |
| `ingress.annotations` | — | Annotations to add to the Ingress |
| `ingress.tls.enabled` | `false` | Whether to configure TLS |
| `ingress.tls.secretName` | — | Name of the TLS secret |

When `ingress.enabled` is `false` or the ingress field is omitted, no Ingress resource is created. If an Ingress was previously created and you disable it, the operator will delete it.

#### API TLS (`spec.tls`)

All three controllers (Pihole, Blocklist, Whitelist) communicate with Pi-hole's API over HTTPS. By default the operator skips TLS certificate verification (`InsecureSkipVerify: true`) because Pi-hole ships with a self-signed certificate.

Use `spec.tls` to tighten this when you manage your own certificates:

```yaml
spec:
  tls:
    insecureSkipVerify: false   # validate the server certificate
    caSecretRef:
      name: pihole-ca-cert      # Secret containing the CA PEM
      key: ca.crt               # optional — defaults to "ca.crt"
```

The referenced Secret must exist in the same namespace as the `Pihole` resource and contain the CA certificate under the specified key.

| Field | Default | Description |
|---|---|---|
| `tls.insecureSkipVerify` | `true` | Skip TLS certificate verification |
| `tls.caSecretRef.name` | — | Name of the Secret containing the CA certificate |
| `tls.caSecretRef.key` | `ca.crt` | Key within the Secret |

#### Server TLS (`spec.serverTLS`)

To have Pi-hole serve your own TLS certificate on its HTTPS endpoint:

```yaml
spec:
  serverTLS:
    secretName: pihole-tls   # standard k8s TLS secret
    # certKey: tls.crt       # defaults to tls.crt
    # keyKey: tls.key        # defaults to tls.key
```

Works with cert-manager: create a `Certificate` resource targeting the Pi-hole service,
then reference the resulting secret here.

Pair with `spec.tls` for full end-to-end verification:

```yaml
spec:
  serverTLS:
    secretName: pihole-tls
  tls:
    enabled: true            # public CA: no caSecretRef needed
    # caSecretRef:           # private CA: provide your CA cert
    #   name: my-ca
    #   key: ca.crt
```

| Field | Default | Description |
|---|---|---|
| `serverTLS.secretName` | — | Name of the Secret containing the TLS certificate and key |
| `serverTLS.certKey` | `tls.crt` | Key within the Secret holding the PEM certificate chain |
| `serverTLS.keyKey` | `tls.key` | Key within the Secret holding the PEM private key |

### Blocklist

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

#### Spec fields

| Field | Default | Description |
|---|---|---|
| `sources` | (required) | List of blocklist URLs (1–100) |
| `enabled` | `true` | Whether the blocklist is active |
| `syncInterval` | `1440` | Re-sync interval in minutes (60–10080) |
| `description` | — | Human-readable description |
| `targetNamespaces` | — | Namespaces to search for Pihole instances (see below) |

#### Cross-namespace targeting

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

### Whitelist

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

#### Spec fields

| Field | Default | Description |
|---|---|---|
| `domains` | (required) | List of domains to whitelist (1–1000) |
| `enabled` | `true` | Whether the whitelist is active |
| `description` | — | Human-readable description |

### PiholeDNSRecord

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

#### Spec fields

| Field | Default | Description |
|---|---|---|
| `hostname` | (required) | DNS hostname (max 253 characters) |
| `recordType` | (required) | Record type: `A`, `AAAA`, or `CNAME` |
| `ipAddress` | — | IP address (required for `A` and `AAAA` records) |
| `cnameTarget` | — | Target hostname (required for `CNAME` records) |
| `description` | — | Human-readable description |
| `targetNamespaces` | — | Namespaces to search for Pihole instances (see below) |

#### Cross-namespace targeting

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

## Examples

See the [`examples/`](examples/) directory for ready-to-use manifests:

- [`pihole.yaml`](examples/pihole.yaml) — minimal Pi-hole with annotated status output
- [`basic.yaml`](examples/basic.yaml) — minimal Pi-hole with defaults
- [`full.yaml`](examples/full.yaml) — all options configured
- [`pihole-loadbalancer.yaml`](examples/pihole-loadbalancer.yaml) — DNS and Web UI exposed via LoadBalancer with static IPs; demonstrates service drift detection
- [`existing-secret.yaml`](examples/existing-secret.yaml) — using a pre-existing Secret for the admin password
- [`resource-limits.yaml`](examples/resource-limits.yaml) — Pi-hole with CPU/memory requests and limits
- [`ingress.yaml`](examples/ingress.yaml) — Pi-hole with Ingress for web UI
- [`upstream-dns-ha.yaml`](examples/upstream-dns-ha.yaml) — custom upstream DNS with HA and PDB
- [`blocklist.yaml`](examples/blocklist.yaml) — ad-blocking blocklist
- [`cross-namespace-blocklist.yaml`](examples/cross-namespace-blocklist.yaml) — Blocklist targeting Piholes in other namespaces
- [`cross-namespace-dnsrecord.yaml`](examples/cross-namespace-dnsrecord.yaml) — PiholeDNSRecord targeting Piholes in other namespaces
- [`whitelist.yaml`](examples/whitelist.yaml) — domain allow list for false positives
- [`dnsrecord.yaml`](examples/dnsrecord.yaml) — local DNS records (A and CNAME)

Apply an example:

```bash
kubectl apply -f examples/basic.yaml
```

## Contributing

Feel free to open a PR with your suggested change!

Run `make help` for available make targets. More info at the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html).

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
