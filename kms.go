package gpgkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// KMSAlgorithm is the only Cloud KMS algorithm supported: OpenPGP v4 RSA
// signatures are PKCS#1 v1.5 (not PSS), and gpgkms always hashes with SHA-256.
const KMSAlgorithm = "RSA_SIGN_PKCS1_4096_SHA256"

// kmsRequestTimeout bounds each Cloud KMS call, so a hung request fails the
// release job quickly instead of running until the CI job's own timeout.
const kmsRequestTimeout = time.Minute

// kmsAttempts is how many times a Cloud KMS call is tried. Release jobs have
// failed on short outages of Google's credential and KMS endpoints (for
// example a 503 while exchanging the workload identity token), so transient
// errors are retried.
const kmsAttempts = 5

// kmsRetryDelay is the wait before the first retry. It doubles after each
// failed attempt (1s, 2s, 4s, 8s), so a call gives up after about 15 seconds
// of waiting plus the time spent in the attempts themselves.
const kmsRetryDelay = time.Second

// hsmProtectionLevels are the Cloud KMS protection levels accepted: the key
// material must stay inside an HSM. SOFTWARE keys and external (EKM) keys are
// rejected.
var hsmProtectionLevels = map[string]bool{"HSM": true, "HSM_SINGLE_TENANT": true}

// KMSSigner is a crypto.Signer backed by a Cloud KMS CryptoKeyVersion with the
// algorithm KMSAlgorithm.
type KMSSigner struct {
	ctx        context.Context
	svc        *cloudkms.ProjectsLocationsKeyRingsCryptoKeysCryptoKeyVersionsService
	name       string
	pub        *rsa.PublicKey
	retryDelay time.Duration
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
// Requests that fail with a transient error are retried a few times with
// exponential backoff.
func NewKMSSigner(ctx context.Context, name string, opts ...option.ClientOption) (*KMSSigner, error) {
	return newKMSSigner(ctx, name, kmsRetryDelay, opts...)
}

// newKMSSigner is NewKMSSigner with a configurable first retry delay, so
// tests do not wait for real backoff.
func newKMSSigner(ctx context.Context, name string, retryDelay time.Duration, opts ...option.ClientOption) (*KMSSigner, error) {
	svc, err := cloudkms.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create Cloud KMS client: %w", err)
	}
	versions := svc.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions

	resp, err := retryKMS(ctx, retryDelay, func(ctx context.Context) (*cloudkms.PublicKey, error) {
		return versions.GetPublicKey(name).Context(ctx).Do()
	})
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
	return &KMSSigner{ctx: ctx, svc: versions, name: name, pub: pub, retryDelay: retryDelay}, nil
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
	// Retrying is safe: signing the same digest again has no side effects, and
	// every returned signature is verified below.
	resp, err := retryKMS(s.ctx, s.retryDelay, func(ctx context.Context) (*cloudkms.AsymmetricSignResponse, error) {
		return s.svc.AsymmetricSign(s.name, &cloudkms.AsymmetricSignRequest{
			Digest: &cloudkms.Digest{Sha256: base64.StdEncoding.EncodeToString(digest)},
		}).Context(ctx).Do()
	})
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

// retryKMS calls do, each time with its own kmsRequestTimeout, until it
// succeeds, fails with an error that is not retryable, ctx ends or kmsAttempts
// calls have failed. The wait between attempts starts at delay and doubles.
func retryKMS[T any](ctx context.Context, delay time.Duration, do func(context.Context) (T, error)) (T, error) {
	for attempt := 1; ; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, kmsRequestTimeout)
		v, err := do(reqCtx)
		cancel()
		if err == nil {
			return v, nil
		}
		if ctx.Err() != nil {
			return v, canceledError(ctx, err)
		}
		if attempt == kmsAttempts || !retryable(err) {
			return v, attemptsError(attempt, err)
		}
		select {
		case <-ctx.Done():
			return v, canceledError(ctx, err)
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// canceledError wraps both the context error, so callers can detect
// cancellation with errors.Is, and the last KMS error, so logs show why the
// attempts failed.
func canceledError(ctx context.Context, err error) error {
	if errors.Is(err, ctx.Err()) {
		return err
	}
	return fmt.Errorf("%w (last error: %w)", ctx.Err(), err)
}

// attemptsError adds the number of attempts to err when there was more than
// one, so CI logs show that retries happened.
func attemptsError(attempts int, err error) error {
	if attempts == 1 {
		return err
	}
	return fmt.Errorf("failed %d attempts: %w", attempts, err)
}

// retryable reports whether a failed Cloud KMS call may succeed if repeated.
// A 4xx response from the KMS API (permission denied, key not found, invalid
// request) is permanent, except 408 and 429. Everything else is retried: 5xx
// responses, network errors, per-request timeouts and failures to fetch
// credentials, which the auth library reports as plain errors.
func retryable(err error) bool {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		return apiErr.Code >= http.StatusInternalServerError ||
			apiErr.Code == http.StatusRequestTimeout ||
			apiErr.Code == http.StatusTooManyRequests
	}
	return true
}
