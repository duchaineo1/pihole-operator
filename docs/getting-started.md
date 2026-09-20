# Getting started

## Install the operator

```bash
helm install pihole-operator oci://ghcr.io/duchaineo1/pihole-operator/charts/pihole-operator \
  --namespace pihole-operator --create-namespace
```

Chart values are documented in [`dist/chart/values.yaml`](https://github.com/duchaineo1/pihole-operator/blob/main/dist/chart/values.yaml).

## Create a Pi-hole

```yaml
apiVersion: pihole-operator.org/v1alpha1
kind: Pihole
metadata:
  name: my-pihole
spec:
  size: 1
  timezone: "America/New_York"
```

```bash
kubectl apply -f pihole.yaml
kubectl get pihole my-pihole -o wide
```

The admin password is generated for you unless you set one. Retrieve it with:

```bash
kubectl get secret my-pihole-admin -o jsonpath='{.data.password}' | base64 -d
```

See [Pihole](pihole.md) for every option.

## Add a blocklist and a DNS record

```yaml
apiVersion: pihole-operator.org/v1alpha1
kind: Blocklist
metadata:
  name: ads
spec:
  sources:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
---
apiVersion: pihole-operator.org/v1alpha1
kind: PiholeDNSRecord
metadata:
  name: nas
spec:
  hostname: nas.home.local
  recordType: A
  ipAddress: "192.168.1.10"
```

Both are applied to every pod of every `Pihole` in the same namespace. To reach other namespaces, see [cross-namespace targeting](blocklist.md#cross-namespace-targeting).

## Try it locally

You can run the operator against a throwaway [kind](https://kind.sigs.k8s.io/) cluster:

```bash
kind create cluster
make install          # install the CRDs
make run              # run the operator from your checkout
kubectl apply -f examples/basic.yaml
```
