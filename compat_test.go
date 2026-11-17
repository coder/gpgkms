package gpgkms

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// coderCoderEntity is the key derivation of coder/coder's scripts/gpgkms
// before it moved here, copied verbatim apart from the identity being passed
// in. coder/coder's release key must keep the same fingerprint and public key
// when it switches to this module, so the outputs must stay byte-identical.
func coderCoderEntity(signer crypto.Signer, created time.Time) (*openpgp.Entity, error) {
	rsaPub := signer.Public().(*rsa.PublicKey)
	pub := packet.NewRSAPublicKey(created, rsaPub)
	priv := &packet.PrivateKey{PublicKey: *pub, PrivateKey: signer}
	e := &openpgp.Entity{
		PrimaryKey: pub,
		PrivateKey: priv,
		Identities: map[string]*openpgp.Identity{},
	}
	f := false
	err := e.AddUserId("Coder Release Signing Key", "", "security@coder.com", &packet.Config{
		DefaultHash:                           crypto.SHA256,
		Time:                                  func() time.Time { return created },
		KeyLifetimeSecs:                       uint32((4 * 365 * 24 * time.Hour) / time.Second),
		NonDeterministicSignaturesViaNotation: &f,
	})
	return e, err
}

func TestCompatibleWithCoderCoder(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	// keyCreated in coder/coder's scripts/gpgkms.
	created := time.Unix(1794787200, 0)

	want, err := coderCoderEntity(signer, created)
	must(t, err)
	got, err := NewEntity(signer, Identity{
		Name:     "Coder Release Signing Key",
		Email:    "security@coder.com",
		Created:  created,
		Lifetime: 4 * 365 * 24 * time.Hour,
	})
	must(t, err)

	if !bytes.Equal(got.PrimaryKey.Fingerprint, want.PrimaryKey.Fingerprint) {
		t.Fatalf("fingerprint %X, want %X", got.PrimaryKey.Fingerprint, want.PrimaryKey.Fingerprint)
	}
	var a, b bytes.Buffer
	must(t, WritePublicKey(&a, got, true))
	must(t, WritePublicKey(&b, want, true))
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("exported public key differs from coder/coder's")
	}
}
