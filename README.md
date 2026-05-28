# signing-keys

Public keys for verifying cosign signatures on EESSI container images and
other signed artifacts. Verifiers reference the raw key URLs from this
repository in `cosign verify --key …` to confirm provenance from the
official Azure DevOps build pipelines.

## Active key

| File | Algorithm | Active since | Registries covered |
|---|---|---|---|
| [`signing.pub`](signing.pub) | EC P-256 (ECDSA) | 2026-05-28 | `eessidockerrepository.azurecr.io` |

Signing is performed server-side in Azure Key Vault (`kv-dkeessi-shared`,
key `eessi-image-signing-ec`). The private key never leaves Key Vault.
Only the official Azure DevOps build pipelines can produce signatures
(Workload Identity Federation, no shared secrets).

## Verifying an image

```sh
cosign verify \
  --key https://raw.githubusercontent.com/ERINA-Community/signing-keys/main/signing.pub \
  eessidockerrepository.azurecr.io/<image>@sha256:<digest>
```

Cosign also checks the signature against the public Rekor transparency
log (`rekor.sigstore.dev`) automatically, providing a tamper-evident
audit trail independent of EESSI infrastructure.

## Key lifecycle

Two distinct update paths exist:

- **Routine rotation** (same algorithm) — new key VERSION under the same
  KV key NAME. Previous public keys are kept here as `signing-vN.pub`
  for verifying historical signatures.
- **Algorithm migration** (e.g. EC P-256 → Ed25519) — new key NAME with a
  new algorithm suffix, published as a new file in this repo (e.g.
  `signing-ed25519.pub`). Old keys remain valid for verifying past
  signatures.
