You are an experienced, pragmatic software engineering AI agent. Do not over-engineer a solution when a simple one is possible. Keep edits minimal. Ask for permission before making an exception to any rule.

# AGENTS.md

## Project Overview

`gpgkms` (module `github.com/coder/gpgkms`) makes OpenPGP (GPG) signatures with an
RSA key held in Google Cloud KMS, so a release signing private key never exists
outside the HSM. It was extracted from coder/coder's `scripts/gpgkms` and is used
by the release jobs of coder/coder and coder/terraform-provider-coder, which
pin it as a Go tool dependency (`go get -tool …@<commit>`).

It is both a Go library (package `gpgkms`) and a CLI (`cmd/gpgkms`) with two
subcommands: `public-key` (export the derived OpenPGP public key) and `sign`
(write a detached signature).

Key terms:

- **Derived key**: the OpenPGP key is not stored anywhere. It is rebuilt on every
  run from the KMS public key, an `Identity` (name, comment, email), a pinned
  creation time (`Created`) and an optional `Lifetime`.
- **Fingerprint**: the OpenPGP v4 fingerprint depends on the RSA public key and
  `Created` only (not the user ID). Consumers and registries pin it, so anything
  that changes it is a breaking change for every user.
- **Determinism**: RSA PKCS#1 v1.5 signatures are deterministic, and go-crypto's
  random salt notation is disabled, so the exported public key (including its
  self-signature) is byte-identical on every run.
- **Prepend**: `sign -prepend` writes an existing binary signature (for example
  from an old `gpg` key) before the KMS signature, for key rotations.

Technology:

- Go (version and patched toolchain pinned in `go.mod`; `toolchain` is bumped
  for security fixes, so `go install` builds with it).
- `github.com/ProtonMail/go-crypto/openpgp` for OpenPGP packets and armor.
- `google.golang.org/api/cloudkms/v1` for KMS, with Application Default
  Credentials. Only the KMS algorithm `RSA_SIGN_PKCS1_4096_SHA256` is supported.
- Standard library `flag` for the CLI. No other frameworks, no database.

**Security posture:** this code runs in release jobs that hold the KMS signer
role. `CODEOWNERS` assigns every file to `@coder/security`, and `SECURITY.md`
says to treat every change like a change to release signing. Consumers pin this
module by commit.

## Reference

| Path | Purpose |
|---|---|
| `gpgkms.go` | `Identity`, `NewEntity` (key derivation and self-signature), `WritePublicKey`, `Sign`, `SignOptions`, `ValidateSignatures`. |
| `kms.go` | `KMSSigner`, a `crypto.Signer` backed by a Cloud KMS CryptoKeyVersion. Checks the KMS algorithm and HSM protection level, only makes PKCS#1 v1.5 signatures of SHA-256 digests, bounds each request with a timeout, retries transient failures with backoff (`retryKMS`), and verifies every KMS signature locally before returning it. |
| `kms_test.go` | Tests `KMSSigner` against a fake Cloud KMS (`httptest` server, `option.WithEndpoint`). Use it for any KMS change; there is no other way to exercise `kms.go` without credentials. |
| `cmd/gpgkms/main.go` | CLI: flag parsing, `-fingerprint` pinning, file I/O. `newSigner` is a package variable swapped in tests. |
| `gpgkms_test.go` | Library tests; `opaqueSigner` hides `*rsa.PrivateKey` so tests use the `crypto.Signer` path like KMS does. |
| `compat_test.go` | Verbatim copy of coder/coder's original derivation; asserts the same fingerprint and byte-identical public key. |
| `golden_test.go` | Pins exported public-key bytes against `testdata/*.asc.golden`. |
| `testdata/test-key.pem` | Throwaway RSA key used only by the golden test. Never use it for anything else. |
| `.github/workflows/ci.yml` | Tests (Linux, macOS), golangci-lint, govulncheck (also weekly), actionlint, zizmor. |
| `.github/dependabot.yml` | Weekly grouped Go (`/` and `/tools`) and Actions updates with a 7-day cooldown. |
| `tools/go.mod` | Separate module pinning golangci-lint and govulncheck, so their dependencies stay out of the library's module graph. Run them with `go tool -modfile=tools/go.mod`. |
| `.golangci.yml` | golangci-lint v2 config (gosec, revive, errorlint, gocritic, nolintlint, goimports with local prefix). |

Data flow: `NewKMSSigner` fetches and validates the KMS public key →
`NewEntity` builds an OpenPGP primary key with `Created` and self-signs the user
ID through the signer → `WritePublicKey` exports it, or `Sign` writes a detached
signature (optionally after prepended signatures, optionally armored). Every
signature calls KMS `AsymmetricSign` through `KMSSigner.Sign`.

## Essential Commands

Run from the repository root. golangci-lint and govulncheck are pinned in
`tools/go.mod`; the actionlint and zizmor versions live in `ci.yml`'s `env`.

```bash
go build ./...                                   # build
gofmt -l . && go vet ./...                       # format check and vet (gofmt -w . to fix)
go test -race -shuffle=on -count=1 ./...         # tests, as CI runs them
go mod tidy -diff && (cd tools && go mod tidy -diff) && go mod verify   # module hygiene, as CI runs it
go tool -modfile=tools/go.mod golangci-lint run ./...                    # lint (also checks gofmt/goimports)
go tool -modfile=tools/go.mod govulncheck ./...                          # vulnerability scan
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12                # workflow lint
pipx run zizmor==1.32.0 .github/                                         # workflow security audit
go clean -testcache                              # clean cached test results
```

There is no dev server. The CLI cannot run against real KMS without credentials
and the signer role; test it through `run()` with a swapped `newSigner` (see
`cmd/gpgkms/main_test.go`).

Regenerate golden files (only when the change is intended; see Anti-patterns):

```bash
go test -run TestGoldenPublicKey -update .
```

Pass `.`, not `./...`: only the root package defines `-update`, so the
`cmd/gpgkms` test binary fails on the unknown flag. The regenerated files
must match the committed ones byte for byte (`git status` stays clean).

## Patterns

- **Reproducible output is a feature.** Any `packet.Config` used for the
  self-signature must set `Time` to `Identity.Created`, `DefaultHash` to SHA-256
  and `NonDeterministicSignaturesViaNotation` to `false`. Otherwise the exported
  key changes on every run.
- **Validate early, with clear errors.** `Identity.validate` bounds `Lifetime` to
  what fits in a `uint32` of seconds; the CLI requires `-key` and `-created`
  before contacting KMS. Error messages say how to fix the input (for example
  `(wrong -key, -created or KMS key?)`).
- **Fail closed on KMS responses.** `NewKMSSigner` rejects keys that are not
  HSM-protected, and `KMSSigner.Sign` rejects PSS and non-SHA-256 input and
  verifies the returned signature with the public key, so a corrupted response
  never becomes a release signature. Keep these checks.
- **Fail closed on inputs that end up in public files.** `ValidateSignatures`
  reads `-prepend` with `packet.Read`, not `packet.Reader.Next` (which silently
  skips unknown and marker packets), and accepts only binary-document
  signatures. The CLI writes `-out` through a temp file and rename, and refuses
  an `-out` that is the file being signed.
- **Errors** are wrapped with `fmt.Errorf("context: %w", err)` and compared with
  `errors.Is` (enforced by errorlint).
- **`//nolint` and `#nosec`** need a specific linter and a reason
  (nolintlint `require-explanation`, `require-specific`), for example
  `//nolint:gosec // validate bounds Lifetime to [0, 2^32-1] seconds`.
- **Tests** use only the standard library (`testing`, no testify), a local
  `must(t, err)` helper, `t.Parallel()` in the library package, and map-driven
  table tests. Generate throwaway keys with `rsa.GenerateKey` (2048 bits is
  enough for tests); verify outputs with go-crypto's `CheckDetachedSignature` or
  `ReadArmoredKeyRing` rather than comparing bytes, except in the golden test.
  `cmd/gpgkms` tests swap the global `newSigner`, so they must not call
  `t.Parallel()`.

## Anti-patterns

- **Changing the fingerprint or exported key bytes.** Never change how `Created`,
  the key packet or the self-signature are built, and never edit
  `compat_test.go`'s `coderCoderEntity` or the golden files to make a test pass.
  Every consumer has published and pinned the current key; a change forces a key
  re-publication. If a dependency update changes the golden output, stop and
  report it.
- **Adding non-deterministic or extra signature data** (salt notations,
  random-based signing, new subpackets) to release signatures. Older verifiers
  and the Terraform Registry consume them.
- **Supporting more KMS algorithms or hashes casually.** OpenPGP v4 RSA uses
  PKCS#1 v1.5, and `KMSSigner` signs only SHA-256 digests; widening this needs a
  security review.
- **Unpinned tooling or actions.** Actions are pinned by commit SHA with a
  version comment, checkouts use `persist-credentials: false`, workflow
  permissions stay `contents: read`, and tools run at exact versions: Go tools
  through `tools/go.mod`, the rest through `ci.yml`'s `env`. actionlint cannot
  move into `tools/go.mod` because of a dependency conflict (see the comment in
  `ci.yml`).
- **New dependencies.** Each one enters a release-signing job. Prefer the
  standard library; ask before adding a module.

## Code Style

- `gofmt` and `goimports` with `github.com/coder/gpgkms` as the local import
  prefix: standard library, third-party, then local imports, each group
  separated by a blank line.
- Every exported identifier has a doc comment that starts with its name
  (revive `exported`). Comments explain why, not what.
- Keep the package flat: library in the root, CLI in `cmd/gpgkms`. Keep
  `README.md`, the `cmd/gpgkms` package doc and the `usage` string in sync when
  flags change.

## Commit and Pull Request Guidelines

Before committing, run and pass: `gofmt -l .` (no output), `go vet ./...`,
`go test -race -shuffle=on -count=1 ./...`, `go mod tidy -diff` (root and
`tools/`), golangci-lint,
and govulncheck. Run actionlint and zizmor when touching `.github/`.

Commit messages use `type: short imperative summary`, lowercase, as in the
history: `deps:` for dependency bumps (Dependabot uses it for Go modules),
`ci:` for workflow and Actions changes, `test:` for tests, and `feat:`, `fix:`,
`docs:` otherwise. PRs are squash-merged, so the PR title becomes the commit
subject.

PR descriptions must say:

- what changed and why;
- whether the exported public key or fingerprint can change (normally: "no,
  golden and compat tests pass unchanged");
- for dependency bumps, that the golden test still passes;
- the validation you ran.

Every PR is reviewed by `@coder/security`. Do not open a PR unless asked.
