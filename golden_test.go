package gpgkms

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// TestGoldenPublicKey pins the exact bytes of an exported public key. Consumers
// commit the exported key and compare against it (and registries and IDE
// plugins hold copies), so a dependency update that changes how the key or its
// self-signature is serialized must fail here rather than in a release job.
// testdata/test-key.pem is a throwaway key used only by this test.
func TestGoldenPublicKey(t *testing.T) {
	t.Parallel()
	pemBytes, err := os.ReadFile("testdata/test-key.pem")
	must(t, err)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block in testdata/test-key.pem")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	must(t, err)

	for name, id := range map[string]Identity{
		"no-expiry": {
			Name: "gpgkms Test Key", Email: "test@example.com",
			Created: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
		},
		// The shape of coder/coder's release key: a comment-less user ID with a lifetime.
		"lifetime": {
			Name: "gpgkms Test Key", Email: "test@example.com",
			Created:  time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC),
			Lifetime: 4 * 365 * 24 * time.Hour,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, err := NewEntity(opaqueSigner{key: key}, id)
			must(t, err)
			var got bytes.Buffer
			must(t, WritePublicKey(&got, e, true))

			path := "testdata/" + name + ".asc.golden"
			if *update {
				must(t, os.WriteFile(path, got.Bytes(), 0o600))
				return
			}
			want, err := os.ReadFile(path)
			must(t, err)
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("exported public key changed (fingerprint %X); a dependency update changed the serialization. "+
					"Do not update the golden file unless every consumer re-publishes its key:\n%s",
					e.PrimaryKey.Fingerprint, strings.TrimSpace(got.String()))
			}
		})
	}
}
