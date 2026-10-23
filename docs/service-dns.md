# DNS records from Services

Annotate a `Service` and the operator creates local DNS records for it in Pi-hole, keeps them pointed at the Service's current IP, and removes them when the annotation or the Service goes away. It works like external-dns, but with your own Pi-hole as the DNS provider.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: jellyfin
  namespace: media
  annotations:
    pihole-operator.org/hostnames: "jellyfin.home.example.com,tv.home.example.com"
    pihole-operator.org/target-namespaces: "pihole-system"
spec:
  type: LoadBalancer
  selector:
    app: jellyfin
  ports:
    - port: 8096
```

Once the LoadBalancer has an IP, each hostname gets its own A record:

```console
$ kubectl get dnsrec -n media
NAME                                  HOSTNAME                    TYPE   LAST SYNC   AGE
jellyfin-jellyfin.home.example.com    jellyfin.home.example.com   A      5s          5s
jellyfin-tv.home.example.com          tv.home.example.com         A      5s          5s
```

## How it works

```
Service (annotated) ──► PiholeDNSRecord (owned by the Service) ──► every Pi-hole pod
```

The operator turns each hostname into a regular [`PiholeDNSRecord`](dnsrecord.md) in the Service's namespace. The record controller then pushes it to Pi-hole, exactly like a record you write by hand: it is applied to every replica, and it never overwrites an entry it didn't create.

- **The Service is the source of truth.** If you edit a generated record, the edit is reverted. If you delete it, it is recreated. To change or remove a record, change the annotation.
- **Deleting the Service deletes its records** through garbage collection (an owner reference). Each record's finalizer then removes its entry from Pi-hole.
- **Hand-written records are never touched.** If a `PiholeDNSRecord` with the generated name already exists and doesn't belong to the Service, it is left alone and the Service gets a `NameCollision` warning event.

Generated records carry these labels:

| Label | Value |
|---|---|
| `pihole-operator.org/managed-by` | `service-dns` |
| `pihole-operator.org/service-uid` | UID of the owning Service |

```sh
# List every record generated from a Service
kubectl get dnsrec -A -l pihole-operator.org/managed-by=service-dns
```

## Annotations

| Annotation | Required | Description |
|---|---|---|
| `pihole-operator.org/hostnames` | yes | Comma-separated hostnames. They are trimmed and lowercased, and invalid names are skipped with an `InvalidHostname` warning event. |
| `pihole-operator.org/target-namespaces` | no | Comma-separated namespaces whose Piholes get the records (`*` for all), with the same meaning as [`targetNamespaces`](dnsrecord.md#cross-namespace-targeting). Defaults to the operator's `--service-dns-default-target-namespaces`, and if that is not set either, to the Service's own namespace. |
| `pihole-operator.org/ip` | no | IPv4 address to use instead of the Service's own address. |
| `pihole-operator.org/use-cluster-ip` | no | Set to `"true"` to fall back to `spec.clusterIP`. Off by default, because LAN clients usually can't reach cluster IPs. |

## Which IP is used

1. The `pihole-operator.org/ip` annotation, if set. It must be an IPv4 address, or the Service gets an `InvalidIP` warning event.
2. For `type: LoadBalancer`, the first IPv4 address in `status.loadBalancer.ingress`.
3. `spec.clusterIP`, if `pihole-operator.org/use-cluster-ip` is `"true"`.

If none applies, no record is created:

- A LoadBalancer still waiting for its address simply waits. The status update that assigns the IP triggers a new reconcile.
- Any other Service type gets a `NoAddress` warning event.

Only A records are created, since IPv6 LoadBalancer addresses are skipped. If the address disappears later (for example while MetalLB restarts), existing records keep their last IP instead of being deleted and recreated.

## Conflicts

If Pi-hole already has an entry for the hostname with a different IP, such as one added in the Pi-hole UI or by another record, the generated record reports `Available=False` with reason `Conflict` and nothing is written. Remove the other entry and the record applies within a minute.

```sh
kubectl get dnsrec -n media jellyfin-jellyfin.home.example.com \
  -o jsonpath='{.status.conditions[?(@.type=="Available")]}'
```

## Operator settings

| Helm value | Manager flag | Default | Description |
|---|---|---|---|
| `serviceDNS.enabled` | `--enable-service-dns` | `true` | Turn the Service watcher on or off. Existing generated records are kept when it is turned off. |
| `serviceDNS.defaultTargetNamespaces` | `--service-dns-default-target-namespaces` | `""` | Target namespaces for Services without the `target-namespaces` annotation. |

If all your Piholes live in one namespace, set the default once instead of annotating every Service:

```yaml
# values.yaml
serviceDNS:
  defaultTargetNamespaces: "pihole-system"
```

## Troubleshooting

Events on the Service explain what happened to it:

```sh
kubectl events -n media --for service/jellyfin
```

| Reason | Meaning |
|---|---|
| `Created` / `Updated` / `Deleted` | A generated record was created, changed (usually a new IP) or removed. |
| `NoAddress` | The Service has no LAN-reachable IP. Use a LoadBalancer, or set `ip` or `use-cluster-ip`. |
| `InvalidIP` | The `ip` annotation is not an IPv4 address. |
| `InvalidHostname` | A hostname in the annotation is not a valid DNS name and was skipped. |
| `NameCollision` | A hand-written `PiholeDNSRecord` already uses the generated name. |

Once a record exists, its own status (`kubectl describe dnsrec ...`) shows whether it reached Pi-hole: `Applied`, `PartiallyApplied`, `Conflict`, `NoPihole` or `ApplyFailed`.
