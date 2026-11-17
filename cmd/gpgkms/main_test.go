package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func useTestSigner(t *testing.T) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	old := newSigner
	newSigner = func(context.Context, string) (crypto.Signer, error) { return key, nil }
	t.Cleanup(func() { newSigner = old })
}

var identityArgs = []string{
	"-key", "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
	"-name", "Coder Terraform Provider", "-email", "security@coder.com",
	"-created", "2026-11-17T00:00:00Z",
}

func TestPublicKeyAndBinarySignature(t *testing.T) {
	useTestSigner(t)
	ctx := context.Background()
	dir := t.TempDir()

	var pub, stderr bytes.Buffer
	if err := run(ctx, append([]string{"public-key"}, identityArgs...), &pub, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	fpr := strings.ToUpper(hex.EncodeToString(keyring[0].PrimaryKey.Fingerprint))
	if !strings.Contains(stderr.String(), fpr) {
		t.Fatalf("stderr does not print the fingerprint: %s", stderr.String())
	}

	file := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(file, []byte("abc  file.zip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := file + ".sig"
	args := append(append([]string{"sign"}, identityArgs...), "-fingerprint", fpr, "-armor=false", "-out", sigPath, file)
	if err := run(ctx, args, &bytes.Buffer{}, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := os.ReadFile(file)
	if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(msg), bytes.NewReader(sig), nil); err != nil {
		t.Fatalf("binary signature does not verify: %v", err)
	}
}

func TestFingerprintPin(t *testing.T) {
	useTestSigner(t)
	var stderr bytes.Buffer
	args := append(append([]string{"public-key"}, identityArgs...), "-fingerprint", strings.Repeat("AB", 20))
	err := run(context.Background(), args, &bytes.Buffer{}, &stderr)
	if err == nil || !strings.Contains(err.Error(), "want ABAB") {
		t.Fatalf("err = %v", err)
	}
}

func TestRequiredFlags(t *testing.T) {
	useTestSigner(t)
	file := writeTestFile(t, "SHA256SUMS", "abc  file.zip\n")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no key":     {[]string{"public-key", "-name", "x", "-created", "2026-11-17T00:00:00Z"}, "-key is required"},
		"no created": {[]string{"public-key", "-key", "k", "-name", "x"}, "-created is required"},
		"bad time":   {[]string{"public-key", "-key", "k", "-name", "x", "-created", "yesterday"}, "-created:"},
		"no out":     {append(append([]string{"sign"}, identityArgs...), file), "-out is required"},
		"no file":    {append(append([]string{"sign"}, identityArgs...), "-out", file+".sig"), "exactly one file"},
		"unknown":    {[]string{"frobnicate"}, "unknown command"},
	} {
		err := run(context.Background(), tc.args, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// writeTestFile writes content to name in a new temporary directory.
func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// publicKey runs public-key with identityArgs and returns the parsed key.
func publicKey(t *testing.T) openpgp.EntityList {
	t.Helper()
	var pub bytes.Buffer
	if err := run(context.Background(), append([]string{"public-key"}, identityArgs...), &pub, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(&pub)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func TestBinaryPublicKey(t *testing.T) {
	useTestSigner(t)
	var pub bytes.Buffer
	if err := run(context.Background(), append([]string{"public-key", "-armor=false"}, identityArgs...), &pub, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(pub.Bytes(), []byte("-----BEGIN")) {
		t.Fatal("-armor=false public key is armored")
	}
	keyring, err := openpgp.ReadKeyRing(&pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyring[0].PrimaryKey.Fingerprint, publicKey(t)[0].PrimaryKey.Fingerprint) {
		t.Fatal("binary and armored public keys differ")
	}
}

func TestSignArmoredWithPrepend(t *testing.T) {
	useTestSigner(t)
	message := "abc  file.zip\n"
	file := writeTestFile(t, "checksums.txt", message)

	// An old software key, as used before a rotation to KMS.
	oldKey, err := openpgp.NewEntity("Old Key", "", "old@example.com", &packet.Config{RSABits: 2048, Algorithm: packet.PubKeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	var oldSig bytes.Buffer
	if err := openpgp.DetachSign(&oldSig, oldKey, strings.NewReader(message), nil); err != nil {
		t.Fatal(err)
	}
	prependPath := file + ".old.sig"
	if err := os.WriteFile(prependPath, oldSig.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	sigPath := file + ".asc"
	args := append(append([]string{"sign"}, identityArgs...), "-prepend", prependPath, "-out", sigPath, file)
	if err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(sig, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Fatalf("signature is not armored by default:\n%s", sig)
	}
	newKey := publicKey(t)
	for name, keyring := range map[string]openpgp.EntityList{"old": {oldKey}, "new": newKey} {
		if _, err := openpgp.CheckArmoredDetachedSignature(keyring, strings.NewReader(message), bytes.NewReader(sig), nil); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
}

func TestSignRefusesToOverwriteInput(t *testing.T) {
	useTestSigner(t)
	file := writeTestFile(t, "SHA256SUMS", "abc  file.zip\n")
	link := file + ".sig"
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	for _, out := range []string{file, link} {
		args := append(append([]string{"sign"}, identityArgs...), "-out", out, file)
		err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "is the file to sign") {
			t.Errorf("-out %s: err = %v", out, err)
		}
	}
	if got, _ := os.ReadFile(file); string(got) != "abc  file.zip\n" {
		t.Fatalf("input changed: %q", got)
	}
}

func TestSignReplacesSymlinkAtomically(t *testing.T) {
	useTestSigner(t)
	file := writeTestFile(t, "SHA256SUMS", "abc  file.zip\n")
	dir := filepath.Dir(file)
	victim := writeTestFile(t, "victim", "do not overwrite")
	sigPath := filepath.Join(dir, "SHA256SUMS.sig")
	if err := os.Symlink(victim, sigPath); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	args := append(append([]string{"sign"}, identityArgs...), "-armor=false", "-out", sigPath, file)
	if err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "do not overwrite" {
		t.Fatalf("symlink target overwritten: %q", got)
	}
	info, err := os.Lstat(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("-out is %v, want a regular file", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Fatalf("-out mode %v, want 0644 (signatures are public)", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("leftover files in %s: %v", dir, entries)
	}
}
