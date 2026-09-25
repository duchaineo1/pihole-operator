# Pihole

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

The operator creates a StatefulSet (one PVC per pod), DNS, Web and headless Services, and a Secret containing the admin password. See [Design](design.md) for details.

## Spec fields

| Field | Default | Description |
|---|---|---|
| `size` | `1` | Number of replicas |
| `adminPassword` | random | Password for the web UI. Omit to auto-generate. |
| `adminPasswordSecretRef` | — | Reference to an existing Secret (see [TLS](tls.md)) |
| `timezone` | `UTC` | Timezone (e.g. `America/New_York`) |
| `storageSize` | `1Gi` | Size of each pod's PVC for Pi-hole data |
| `storageClass` | cluster default | Storage class for the PVC |
| `dnsServiceType` | `NodePort` | Service type for DNS (`ClusterIP`, `NodePort`, `LoadBalancer`) |
| `webServiceType` | `ClusterIP` | Service type for the web UI |
| `dnsLoadBalancerIP` | — | Static IP for DNS LoadBalancer |
| `dnsExternalTrafficPolicy` | `Local` | `externalTrafficPolicy` of the DNS Service (`Local`, `Cluster`). `Local` preserves client IPs in the Pi-hole query log; `Cluster` makes every node accept DNS but Pi-hole only sees node IPs. Ignored for `ClusterIP`. |
| `webLoadBalancerIP` | — | Static IP for Web LoadBalancer |
| `image` | `docker.io/pihole/pihole:2025.11.0` | Container image |
| `resources` | — | CPU/memory requests and limits (standard Kubernetes resource requirements) |
| `upstreamDNS` | Pi-hole defaults | List of upstream DNS servers (e.g. `["1.1.1.1", "9.9.9.9"]`) |
| `ingress` | — | Ingress configuration for the web UI (see [TLS](tls.md)) |
| `tls` | — | TLS verification settings for Pi-hole API communication (see [TLS](tls.md)) |
| `serverTLS` | — | TLS certificate for Pi-hole's own HTTPS endpoint (see [TLS](tls.md)) |

> **Service drift detection:** If you change `dnsServiceType`, `webServiceType`, `dnsLoadBalancerIP`, `dnsExternalTrafficPolicy`, or `webLoadBalancerIP` after the Pihole resource is created, the operator automatically detects the difference and updates the existing Service on the next reconcile. No manual deletion of the Service is required.

## Status fields

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

## Admin password

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

## Resource limits

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

## Upstream DNS

Override Pi-hole's default upstream DNS servers:

```yaml
spec:
  upstreamDNS:
    - "1.1.1.1"
    - "1.0.0.1"
    - "9.9.9.9"
```

## High availability

When `size` is greater than 1, each instance gets its own PVC and the operator syncs blocklists and DNS records to every pod individually. A PodDisruptionBudget is automatically created with `minAvailable: 1` to ensure at least one Pi-hole pod survives voluntary disruptions.

```yaml
spec:
  size: 3
```

### Web UI with multiple replicas

Pi-hole keeps web UI login sessions in memory on each pod, so spreading UI traffic across replicas logs you out as requests land on a pod that doesn't know your session. The web Service therefore targets **one pod at a time**, selected with the `statefulset.kubernetes.io/pod-name` label:

- Initially the lowest-ordinal Ready pod (usually `<name>-0`).
- If that pod stops being Ready, the operator switches the Service to the next Ready pod within seconds. You will need to log in again.
- When the original pod recovers, the Service stays where it is, so you aren't logged out a second time.

This works regardless of what sits in front of the Service (Ingress, Gateway API, LoadBalancer, `kubectl port-forward`). DNS is unaffected: the DNS Service still balances across all pods.

Changes made in the web UI apply only to the pod currently serving it. Manage blocklists, whitelists and DNS records through their custom resources so they reach every pod.

## Ingress

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
