package gpgkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

// KMSAlgorithm is the only Cloud KMS algorithm supported: OpenPGP v4 RSA
// signatures are PKCS#1 v1.5 (not PSS), and gpgkms always hashes with SHA-256.
const KMSAlgorithm = "RSA_SIGN_PKCS1_4096_SHA256"

// kmsRequestTimeout bounds each Cloud KMS call, so a hung request fails the
// release job quickly instead of running until the CI job's own timeout.
const kmsRequestTimeout = time.Minute

// hsmProtectionLevels are the Cloud KMS protection levels accepted: the key
// material must stay inside an HSM. SOFTWARE keys and external (EKM) keys are
// rejected.
var hsmProtectionLevels = map[string]bool{"HSM": true, "HSM_SINGLE_TENANT": true}

// KMSSigner is a crypto.Signer backed by a Cloud KMS CryptoKeyVersion with the
// algorithm KMSAlgorithm.
type KMSSigner struct {
	ctx  context.Context
	svc  *cloudkms.ProjectsLocationsKeyRingsCryptoKeysCryptoKeyVersionsService
	name string
	pub  *rsa.PublicKey
}

// NewKMSSigner returns a signer for the CryptoKeyVersion name, e.g.
// projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1.
// Credentials come from Application Default Credentials unless opts override
// them. The key must have the algorithm KMSAlgorithm and an HSM protection
// level. The caller needs roles/cloudkms.publicKeyViewer, and
// roles/cloudkms.signer to sign.
//
// ctx is used for every later Sign call too, because crypto.Signer has no
// context parameter; each KMS request is additionally limited to one minute.
func NewKMSSigner(ctx context.Context, name string, opts ...option.ClientOption) (*KMSSigner, error) {
	svc, err := cloudkms.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create Cloud KMS client: %w", err)
	}
	versions := svc.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions

	reqCtx, cancel := context.WithTimeout(ctx, kmsRequestTimeout)
	defer cancel()
	resp, err := versions.GetPublicKey(name).Context(reqCtx).Do()
	if err != nil {
		return nil, fmt.Errorf("get public key for %q: %w", name, err)
	}
	if resp.Algorithm != KMSAlgorithm {
		return nil, fmt.Errorf("key %q has algorithm %s, want %s", name, resp.Algorithm, KMSAlgorithm)
	}
	if !hsmProtectionLevels[resp.ProtectionLevel] {
		return nil, fmt.Errorf("key %q has protection level %q, want HSM", name, resp.ProtectionLevel)
	}
	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return nil, fmt.Errorf("decode public key PEM for %q", name)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key for %q: %w", name, err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key %q is %T, want RSA", name, parsed)
	}
	return &KMSSigner{ctx: ctx, svc: versions, name: name, pub: pub}, nil
}

// Public implements crypto.Signer.
func (s *KMSSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign implements crypto.Signer. It only makes PKCS#1 v1.5 signatures of
// SHA-256 digests.
func (s *KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("RSA-PSS requested: %s only makes PKCS#1 v1.5 signatures", KMSAlgorithm)
	}
	if opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, fmt.Errorf("unsupported hash %v: %s only signs SHA-256 digests", opts.HashFunc(), KMSAlgorithm)
	}
	ctx, cancel := context.WithTimeout(s.ctx, kmsRequestTimeout)
	defer cancel()
	resp, err := s.svc.AsymmetricSign(s.name, &cloudkms.AsymmetricSignRequest{
		Digest: &cloudkms.Digest{Sha256: base64.StdEncoding.EncodeToString(digest)},
	}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("cloud KMS asymmetric sign: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode Cloud KMS signature: %w", err)
	}
	// Check the signature locally so a corrupted response fails here rather
	// than producing an unverifiable release signature.
	if err := rsa.VerifyPKCS1v15(s.pub, crypto.SHA256, digest, sig); err != nil {
		return nil, fmt.Errorf("verify Cloud KMS signature: %w", err)
	}
	return sig, nil
}
