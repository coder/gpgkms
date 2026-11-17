package gpgkms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// opaqueSigner hides the concrete *rsa.PrivateKey type, like a KMS-backed
// signer does, so the tests exercise the crypto.Signer path.
type opaqueSigner struct {
	key *rsa.PrivateKey
}

func (s opaqueSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func newTestSigner(t *testing.T) crypto.Signer {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		testKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	})
	return opaqueSigner{key: testKey}
}

var testIdentity = Identity{
	Name:     "Coder Release Signing Key",
	Email:    "security@coder.com",
	Created:  time.Unix(1794700000, 0),
	Lifetime: 4 * 365 * 24 * time.Hour,
}

const testUserID = "Coder Release Signing Key <security@coder.com>"

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicKeyIsDeterministic(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)

	export := func() []byte {
		e, err := NewEntity(signer, testIdentity)
		must(t, err)
		var buf bytes.Buffer
		must(t, WritePublicKey(&buf, e, true))
		return buf.Bytes()
	}
	first := export()
	if !bytes.Equal(first, export()) {
		t.Fatal("public key export is not deterministic")
	}

	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(first))
	must(t, err)
	if len(keyring) != 1 {
		t.Fatalf("got %d keys", len(keyring))
	}
	key := keyring[0]
	if key.PrimaryKey.CreationTime.Unix() != testIdentity.Created.Unix() {
		t.Fatalf("creation time %v", key.PrimaryKey.CreationTime)
	}
	if len(key.Subkeys) != 0 {
		t.Fatal("unexpected subkeys")
	}
	ident, ok := key.Identities[testUserID]
	if !ok {
		t.Fatalf("missing identity %q", testUserID)
	}
	sig := ident.SelfSignature
	if sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs != uint32(testIdentity.Lifetime/time.Second) {
		t.Fatalf("key lifetime %v", sig.KeyLifetimeSecs)
	}
	if !sig.FlagSign || !sig.FlagCertify {
		t.Fatal("key flags must allow signing and certification")
	}
}

func TestNoLifetimeNeverExpires(t *testing.T) {
	t.Parallel()
	id := testIdentity
	id.Lifetime = 0
	e, err := NewEntity(newTestSigner(t), id)
	must(t, err)
	sig := e.Identities[testUserID].SelfSignature
	if sig.KeyLifetimeSecs != nil && *sig.KeyLifetimeSecs != 0 {
		t.Fatalf("lifetime %d, want none", *sig.KeyLifetimeSecs)
	}
}

func TestIdentityValidation(t *testing.T) {
	t.Parallel()
	for name, id := range map[string]Identity{
		"no name":    {Created: time.Unix(1, 0)},
		"no created": {Name: "x"},
		"negative":   {Name: "x", Created: time.Unix(1, 0), Lifetime: -time.Hour},
	} {
		if _, err := NewEntity(newTestSigner(t), id); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestFingerprintDependsOnCreated(t *testing.T) {
	t.Parallel()
	a, err := NewEntity(newTestSigner(t), testIdentity)
	must(t, err)
	id := testIdentity
	id.Created = id.Created.Add(time.Second)
	b, err := NewEntity(newTestSigner(t), id)
	must(t, err)
	if bytes.Equal(a.PrimaryKey.Fingerprint, b.PrimaryKey.Fingerprint) {
		t.Fatal("fingerprint must change with the creation time")
	}
	id = testIdentity
	id.Name = "Other"
	c, err := NewEntity(newTestSigner(t), id)
	must(t, err)
	if !bytes.Equal(a.PrimaryKey.Fingerprint, c.PrimaryKey.Fingerprint) {
		t.Fatal("fingerprint must not depend on the user ID")
	}
}

func TestSignBinaryVerifies(t *testing.T) {
	t.Parallel()
	e, err := NewEntity(newTestSigner(t), testIdentity)
	must(t, err)
	message := []byte("terraform-provider-coder_2.21.0_SHA256SUMS contents\n")

	var sig bytes.Buffer
	must(t, Sign(&sig, e, bytes.NewReader(message), SignOptions{}))
	if bytes.HasPrefix(sig.Bytes(), []byte("-----BEGIN")) {
		t.Fatal("binary signature is armored")
	}
	must(t, ValidateSignatures(sig.Bytes()))

	signer, err := openpgp.CheckDetachedSignature(openpgp.EntityList{e}, bytes.NewReader(message), bytes.NewReader(sig.Bytes()), nil)
	must(t, err)
	if signer.PrimaryKey.KeyId != e.PrimaryKey.KeyId {
		t.Fatal("wrong signer")
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{e}, strings.NewReader("tampered"), bytes.NewReader(sig.Bytes()), nil); err == nil {
		t.Fatal("tampered message verified")
	}
}

func TestSignWithPrependedSignature(t *testing.T) {
	t.Parallel()
	message := []byte("coder_v2.0.0_checksums.txt contents\n")

	// The old key is an ordinary software key, like the one gpg signs with.
	oldKey, err := openpgp.NewEntity("Old Key", "", "old@example.com", &packet.Config{RSABits: 2048, Algorithm: packet.PubKeyAlgoRSA})
	must(t, err)
	var oldSig bytes.Buffer
	must(t, openpgp.DetachSign(&oldSig, oldKey, bytes.NewReader(message), nil))

	newKey, err := NewEntity(newTestSigner(t), testIdentity)
	must(t, err)

	var out bytes.Buffer
	must(t, Sign(&out, newKey, bytes.NewReader(message), SignOptions{Prepend: oldSig.Bytes(), Armored: true}))

	block, err := armor.Decode(bytes.NewReader(out.Bytes()))
	must(t, err)
	if block.Type != openpgp.SignatureType {
		t.Fatalf("armor type %q", block.Type)
	}
	reader := packet.NewReader(block.Body)
	var issuers []uint64
	for {
		p, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		must(t, err)
		sig, ok := p.(*packet.Signature)
		if !ok || sig.IssuerKeyId == nil {
			t.Fatalf("unexpected packet %T", p)
		}
		issuers = append(issuers, *sig.IssuerKeyId)
	}
	if len(issuers) != 2 || issuers[0] != oldKey.PrimaryKey.KeyId || issuers[1] != newKey.PrimaryKey.KeyId {
		t.Fatalf("issuers %x", issuers)
	}
	for _, key := range []*openpgp.Entity{oldKey, newKey} {
		signer, err := openpgp.CheckArmoredDetachedSignature(openpgp.EntityList{key}, bytes.NewReader(message), bytes.NewReader(out.Bytes()), nil)
		must(t, err)
		if signer.PrimaryKey.KeyId != key.PrimaryKey.KeyId {
			t.Fatal("wrong signer")
		}
	}
}

func TestSignRejectsArmoredPrepend(t *testing.T) {
	t.Parallel()
	newKey, err := NewEntity(newTestSigner(t), testIdentity)
	must(t, err)

	var armored bytes.Buffer
	aw, err := armor.Encode(&armored, openpgp.SignatureType, nil)
	must(t, err)
	must(t, openpgp.DetachSign(aw, newKey, strings.NewReader("x"), nil))
	must(t, aw.Close())

	var out bytes.Buffer
	err = Sign(&out, newKey, strings.NewReader("x"), SignOptions{Prepend: armored.Bytes()})
	if err == nil || !strings.Contains(err.Error(), "prepend signature") {
		t.Fatalf("err = %v", err)
	}
}
