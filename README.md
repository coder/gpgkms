# gpgkms

OpenPGP (GPG) signatures from an RSA key held in Google Cloud KMS, so a release
signing key never exists outside the HSM. Extracted from coder/coder's
`scripts/gpgkms`.

The OpenPGP key is derived from the KMS public key, a user ID and a pinned
creation time. Signing is RSA PKCS#1 v1.5 (deterministic), so the exported
public key, including its self-signature, is byte-identical every time.

## CLI

```bash
go run github.com/coder/gpgkms/cmd/gpgkms@<commit> public-key IDENTITY > key.asc
go run github.com/coder/gpgkms/cmd/gpgkms@<commit> sign IDENTITY -out SHA256SUMS.sig -armor=false SHA256SUMS
```

`IDENTITY` is the same set of flags for both commands:

| Flag | |
|---|---|
| `-key` | CryptoKeyVersion, e.g. `projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1`. Algorithm `RSA_SIGN_PKCS1_4096_SHA256`. |
| `-name`, `-comment`, `-email` | OpenPGP user ID. |
| `-created` | Key creation time (RFC 3339). **Part of the fingerprint: never change it.** |
| `-lifetime` | Validity from `-created` (Go duration, e.g. `35040h`). 0 = never expires. |
| `-fingerprint` | Fail unless the derived key has this fingerprint. Use it in CI to pin the identity. |

`sign` writes an ASCII-armored signature by default; `-armor=false` writes a
binary one, which the Terraform Registry requires for `SHA256SUMS.sig`.
`-prepend <binary sig>` puts an existing signature (for example one made by
`gpg --detach-sign` with an old key) before the KMS one, for key rotations.

Credentials come from Application Default Credentials, for example
`google-github-actions/auth` with workload identity federation. The identity
needs `roles/cloudkms.publicKeyViewer` and `roles/cloudkms.signer` on the key.

## Minting the public key

Publishing the public key needs a self-signature, which needs the signer role.
Mint it from the same reviewed CI job that signs releases (not locally), commit
it, and from then on pass `-fingerprint` so a changed `-created` or key fails
the job instead of silently producing a different key.

## Library

```go
signer, err := gpgkms.NewKMSSigner(ctx, keyVersion)
entity, err := gpgkms.NewEntity(signer, gpgkms.Identity{
	Name: "Example Release Key", Email: "security@example.com",
	Created: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
})
err = gpgkms.Sign(w, entity, file, gpgkms.SignOptions{})
```

## Users

| Repository | Key | Identity |
|---|---|---|
| coder/coder | `coder-release-signing/release-signing/gpg-release` | `Coder Release Signing Key <security@coder.com>`, created `2026-11-16T00:00:00Z`, lifetime `35040h` |
| coder/terraform-provider-coder | `coder-release-signing/release-signing/gpg-terraform-provider` | see its `release.yml` |

`compat_test.go` checks that coder/coder's identity derives the same key as the
original `scripts/gpgkms`, so coder/coder can switch to this module without
changing its fingerprint.

## Development

```bash
go test -race ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

CI runs the tests on Linux and macOS, golangci-lint, govulncheck (also weekly),
and actionlint plus zizmor on the workflows. Dependabot proposes grouped Go and
Actions updates weekly, after a 7-day cooldown. `go.mod` pins a patched
toolchain, so `go install` of the command builds with it.
