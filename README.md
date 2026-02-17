# pihole-operator

A Kubernetes operator to declaratively deploy and configure Pi-hole instances.

## Features

- [x] Deploy Pi-hole with a single custom resource
- [x] Manage blocklists declaratively
- [x] Whitelist management
- [x] DNS record management

## Installation

```bash
git clone https://github.com/duchaineo1/pihole-operator.git
cd pihole-operator/
pushd dist/chart
helm install -n pihole-operator pihole-operator . -f values.yaml
popd
```

## Usage

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
| `image` | `docker.io/pihole/pihole:2025.11.0` | Container image |

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
| `sources` | (required) | List of blocklist URLs (1-100) |
| `enabled` | `true` | Whether the blocklist is active |
| `syncInterval` | `1440` | Re-sync interval in minutes (60-10080) |
| `description` | — | Human-readable description |

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
| `domains` | (required) | List of domains to whitelist (1-1000) |
| `enabled` | `true` | Whether the whitelist is active |
| `description` | — | Human-readable description |

## Examples

See the [`examples/`](examples/) directory for ready-to-use manifests:

- [`basic.yaml`](examples/basic.yaml) — minimal Pi-hole with defaults
- [`full.yaml`](examples/full.yaml) — all options configured
- [`existing-secret.yaml`](examples/existing-secret.yaml) — using a pre-existing Secret for the admin password
- [`blocklist.yaml`](examples/blocklist.yaml) — ad-blocking blocklist
- [`whitelist.yaml`](examples/whitelist.yaml) — domain allow list for false positives

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
