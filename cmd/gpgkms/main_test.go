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
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
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
	for name, args := range map[string][]string{
		"no key":     {"public-key", "-name", "x", "-created", "2026-11-17T00:00:00Z"},
		"no created": {"public-key", "-key", "k", "-name", "x"},
		"bad time":   {"public-key", "-key", "k", "-name", "x", "-created", "yesterday"},
		"no out":     append(append([]string{"sign"}, identityArgs...), "file"),
		"unknown":    {"frobnicate"},
	} {
		if err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
