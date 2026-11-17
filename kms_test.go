package gpgkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

const testKeyVersion = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

// fakeKMS serves the two Cloud KMS endpoints KMSSigner uses, backed by a
// software RSA key.
type fakeKMS struct {
	publicKey cloudkms.PublicKey
	// sign makes the signature returned by asymmetricSign.
	sign func(r *http.Request, digest []byte) []byte
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	key := newTestSigner(t).(opaqueSigner).key
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(t, err)
	return &fakeKMS{
		publicKey: cloudkms.PublicKey{
			Name:            testKeyVersion,
			Algorithm:       KMSAlgorithm,
			ProtectionLevel: "HSM",
			Pem:             string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		},
		sign: func(_ *http.Request, digest []byte) []byte {
			sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest)
			if err != nil {
				panic(err)
			}
			return sig
		},
	}
}

// signer starts the fake server and returns a KMSSigner connected to it.
func (f *fakeKMS) signer(ctx context.Context, t *testing.T) (*KMSSigner, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/"+testKeyVersion+"/publicKey":
			resp = &f.publicKey
		case r.Method == http.MethodPost && r.URL.Path == "/v1/"+testKeyVersion+":asymmetricSign":
			var req cloudkms.AsymmetricSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			digest, err := base64.StdEncoding.DecodeString(req.Digest.Sha256)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			resp = &cloudkms.AsymmetricSignResponse{Signature: base64.StdEncoding.EncodeToString(f.sign(r, digest))}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return NewKMSSigner(ctx, testKeyVersion, option.WithEndpoint(srv.URL+"/"), option.WithHTTPClient(srv.Client()))
}

func TestKMSSignerSignsVerifiableSignatures(t *testing.T) {
	t.Parallel()
	for _, level := range []string{"HSM", "HSM_SINGLE_TENANT"} {
		f := newFakeKMS(t)
		f.publicKey.ProtectionLevel = level
		signer, err := f.signer(context.Background(), t)
		must(t, err)

		e, err := NewEntity(signer, testIdentity)
		must(t, err)
		var sig bytes.Buffer
		must(t, Sign(&sig, e, strings.NewReader("release"), SignOptions{}))
		if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{e}, strings.NewReader("release"), &sig, nil); err != nil {
			t.Errorf("%s: %v", level, err)
		}
	}
}

func TestKMSSignerRejectsKey(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	must(t, err)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}))

	for name, tc := range map[string]struct {
		edit func(*cloudkms.PublicKey)
		want string
	}{
		"wrong algorithm":   {func(k *cloudkms.PublicKey) { k.Algorithm = "RSA_SIGN_PSS_4096_SHA256" }, "algorithm"},
		"software key":      {func(k *cloudkms.PublicKey) { k.ProtectionLevel = "SOFTWARE" }, "protection level"},
		"external key":      {func(k *cloudkms.PublicKey) { k.ProtectionLevel = "EXTERNAL" }, "protection level"},
		"no protection set": {func(k *cloudkms.PublicKey) { k.ProtectionLevel = "" }, "protection level"},
		"bad PEM":           {func(k *cloudkms.PublicKey) { k.Pem = "not PEM" }, "decode public key PEM"},
		"bad DER":           {func(k *cloudkms.PublicKey) { k.Pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n" }, "parse public key"},
		"not RSA":           {func(k *cloudkms.PublicKey) { k.Pem = ecPEM }, "want RSA"},
	} {
		f := newFakeKMS(t)
		tc.edit(&f.publicKey)
		if _, err := f.signer(context.Background(), t); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestKMSSignerRejectsUnsupportedSignOpts(t *testing.T) {
	t.Parallel()
	signer, err := newFakeKMS(t).signer(context.Background(), t)
	must(t, err)
	sha256Digest := sha256.Sum256([]byte("x"))
	sha512Digest := sha512.Sum512([]byte("x"))

	for name, tc := range map[string]struct {
		digest []byte
		opts   crypto.SignerOpts
	}{
		"PSS":          {sha256Digest[:], &rsa.PSSOptions{Hash: crypto.SHA256}},
		"SHA-512":      {sha512Digest[:], crypto.SHA512},
		"short digest": {sha256Digest[:31], crypto.SHA256},
	} {
		if _, err := signer.Sign(rand.Reader, tc.digest, tc.opts); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := signer.Sign(rand.Reader, sha256Digest[:], crypto.SHA256); err != nil {
		t.Fatalf("SHA-256 PKCS#1 v1.5: %v", err)
	}
}

func TestKMSSignerRejectsCorruptSignature(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t)
	sign := f.sign
	f.sign = func(r *http.Request, digest []byte) []byte {
		sig := sign(r, digest)
		sig[len(sig)-1] ^= 1
		return sig
	}
	signer, err := f.signer(context.Background(), t)
	must(t, err)
	digest := sha256.Sum256([]byte("x"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), "verify Cloud KMS signature") {
		t.Fatalf("err = %v", err)
	}
}

func TestKMSSignerStopsWhenContextEnds(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t)
	f.sign = func(r *http.Request, _ []byte) []byte {
		<-r.Context().Done() // hang until the client gives up
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	signer, err := f.signer(ctx, t)
	must(t, err)

	done := make(chan error, 1)
	go func() {
		digest := sha256.Sum256([]byte("x"))
		_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want error from a hung KMS request")
		}
	case <-time.After(time.Minute):
		t.Fatal("Sign did not return after its context ended")
	}
}
