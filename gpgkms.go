// Package gpgkms creates OpenPGP keys and signatures backed by an RSA key held
// in Google Cloud KMS, so a release signing private key never leaves KMS.
//
// The OpenPGP key is derived from the KMS public key, an Identity and a pinned
// creation time. The creation time is part of the OpenPGP fingerprint, so it
// must stay the same for the lifetime of the key. RSA PKCS#1 v1.5 signatures
// are deterministic, so the exported public key (including its self-signature)
// is identical every time it is generated.
package gpgkms

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Identity describes the OpenPGP key derived from a KMS key. Every field except
// Lifetime is part of what users and registries pin: changing Created changes
// the fingerprint, and changing Name, Comment or Email changes the user ID.
type Identity struct {
	Name    string
	Comment string
	Email   string
	// Created is the OpenPGP key creation time. Never change it for an existing
	// key: it is part of the fingerprint.
	Created time.Time
	// Lifetime is the key's validity period from Created. Zero means it never
	// expires.
	Lifetime time.Duration
}

func (id Identity) validate() error {
	if id.Name == "" {
		return errors.New("identity name is required")
	}
	if id.Created.IsZero() {
		return errors.New("identity creation time is required (it is part of the fingerprint)")
	}
	if id.Lifetime < 0 || id.Lifetime/time.Second > 1<<32-1 {
		return fmt.Errorf("invalid key lifetime %s", id.Lifetime)
	}
	return nil
}

// NewEntity builds the OpenPGP key for signer. The result only depends on the
// signer's public key and id, so it is the same on every call.
func NewEntity(signer crypto.Signer, id Identity) (*openpgp.Entity, error) {
	if err := id.validate(); err != nil {
		return nil, err
	}
	rsaPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type %T, want RSA", signer.Public())
	}

	// packet.NewSignerPrivateKey only accepts concrete key types, so build the
	// private key by hand. go-crypto signs RSA keys through crypto.Signer.
	pub := packet.NewRSAPublicKey(id.Created, rsaPub)
	priv := &packet.PrivateKey{PublicKey: *pub, PrivateKey: signer}
	e := &openpgp.Entity{
		PrimaryKey: pub,
		PrivateKey: priv,
		Identities: map[string]*openpgp.Identity{},
	}
	deterministic := false
	err := e.AddUserId(id.Name, id.Comment, id.Email, &packet.Config{
		DefaultHash:     crypto.SHA256,
		Time:            func() time.Time { return id.Created },
		KeyLifetimeSecs: uint32(id.Lifetime / time.Second),
		// go-crypto adds a random salt notation to v4 signatures by default,
		// which would change the exported key every time.
		NonDeterministicSignaturesViaNotation: &deterministic,
	})
	if err != nil {
		return nil, fmt.Errorf("self-sign user ID: %w", err)
	}
	return e, nil
}

// WritePublicKey writes the public key of e, armored unless armored is false.
func WritePublicKey(w io.Writer, e *openpgp.Entity, armored bool) error {
	if !armored {
		return e.Serialize(w)
	}
	aw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	if err := e.Serialize(aw); err != nil {
		return fmt.Errorf("serialize public key: %w", err)
	}
	if err := aw.Close(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(w)
	return err
}

// SignOptions configures Sign.
type SignOptions struct {
	// Prepend is an existing binary (unarmored) detached signature, such as one
	// made by `gpg --detach-sign`. Its signature packets are written before the
	// new signature, so a file can be signed by an old and a new key at once.
	Prepend []byte
	// Armored writes an ASCII-armored signature (.asc). Otherwise the signature
	// is binary (.sig), which is what the Terraform Registry requires.
	Armored bool
	// Time is the signature creation time. Zero means now.
	Time time.Time
}

// Sign writes a detached signature over message made with e.
func Sign(w io.Writer, e *openpgp.Entity, message io.Reader, opts SignOptions) error {
	if len(opts.Prepend) > 0 {
		if err := ValidateSignatures(opts.Prepend); err != nil {
			return fmt.Errorf("prepend signature: %w", err)
		}
	}
	now := opts.Time
	if now.IsZero() {
		now = time.Now()
	}

	out := w
	var aw io.WriteCloser
	if opts.Armored {
		var err error
		aw, err = armor.Encode(w, openpgp.SignatureType, nil)
		if err != nil {
			return err
		}
		out = aw
	}
	if _, err := out.Write(opts.Prepend); err != nil {
		return err
	}
	deterministic := false
	err := openpgp.DetachSign(out, e, message, &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return now },
		// Keep release signatures to the standard subpackets for older verifiers.
		NonDeterministicSignaturesViaNotation: &deterministic,
	})
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if aw == nil {
		return nil
	}
	if err := aw.Close(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(w)
	return err
}

// ValidateSignatures checks that b is a binary stream of one or more OpenPGP
// signature packets and nothing else.
func ValidateSignatures(b []byte) error {
	reader := packet.NewReader(bytes.NewReader(b))
	count := 0
	for {
		p, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("parse packet (the signature must be binary, not armored): %w", err)
		}
		if _, ok := p.(*packet.Signature); !ok {
			return fmt.Errorf("unexpected %T packet, want only signatures", p)
		}
		count++
	}
	if count == 0 {
		return errors.New("no signature packets found")
	}
	return nil
}
