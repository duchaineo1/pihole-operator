# TLS

## API TLS (`spec.tls`)

The Pihole, Blocklist, Whitelist and PiholeDNSRecord controllers communicate with Pi-hole's API over HTTPS. By default the operator skips TLS certificate verification because Pi-hole ships with a self-signed certificate.

Use `spec.tls` to tighten this when you manage your own certificates:

```yaml
spec:
  tls:
    enabled: true               # verify the server certificate
    caSecretRef:                # only needed for a private CA
      name: pihole-ca-cert      # Secret containing the CA PEM
      key: ca.crt               # required — key holding the PEM CA certificate
```

The referenced Secret must exist in the same namespace as the `Pihole` resource and contain the CA certificate under the specified key.

| Field | Default | Description |
|---|---|---|
| `tls.enabled` | `false` | Verify the server certificate. Public CAs need no further config; for a private CA set `caSecretRef`. |
| `tls.caSecretRef.name` | — | Name of the Secret containing the CA certificate |
| `tls.caSecretRef.key` | (required) | Key within the Secret holding the PEM CA certificate |

## Server TLS (`spec.serverTLS`)

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
