// Command gpgkms creates OpenPGP signatures with an RSA key held in Google
// Cloud KMS. See the github.com/coder/gpgkms package for how the OpenPGP key is
// derived.
//
// Usage:
//
//	gpgkms public-key IDENTITY [-armor=false]
//	gpgkms sign IDENTITY [-armor=false] [-prepend <sig>] -out <file> <file-to-sign>
//
// IDENTITY is:
//
//	-key <version> -name <name> [-comment <comment>] [-email <email>]
//	-created <RFC 3339 time> [-lifetime <duration>] [-fingerprint <hex>]
//
// <version> is a CryptoKeyVersion resource name with the algorithm
// RSA_SIGN_PKCS1_4096_SHA256. -created is part of the fingerprint and must
// never change for a key. -fingerprint makes the command fail unless the
// derived key has exactly that fingerprint, which pins the identity in CI.
// Credentials come from Application Default Credentials.
package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/coder/gpgkms"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gpgkms:", err)
		os.Exit(1)
	}
}

const usage = `usage: gpgkms public-key IDENTITY [-armor=false]
       gpgkms sign IDENTITY [-armor=false] [-prepend <sig>] -out <file> <file-to-sign>

IDENTITY: -key <version> -name <name> [-comment <c>] [-email <e>]
          -created <RFC 3339> [-lifetime <duration>] [-fingerprint <hex>]`

// newSigner is replaced in tests.
var newSigner = func(ctx context.Context, key string) (crypto.Signer, error) {
	return gpgkms.NewKMSSigner(ctx, key)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New(usage)
	}
	switch args[0] {
	case "public-key":
		return runPublicKey(ctx, args[1:], stdout, stderr)
	case "sign":
		return runSign(ctx, args[1:], stderr)
	case "-h", "--help", "help":
		_, _ = fmt.Fprintln(stdout, usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n%s", args[0], usage)
}

type identityFlags struct {
	key         string
	name        string
	comment     string
	email       string
	created     string
	lifetime    time.Duration
	fingerprint string
}

func (f *identityFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.key, "key", "", "Cloud KMS CryptoKeyVersion resource name")
	fs.StringVar(&f.name, "name", "", "OpenPGP user ID name")
	fs.StringVar(&f.comment, "comment", "", "OpenPGP user ID comment")
	fs.StringVar(&f.email, "email", "", "OpenPGP user ID email")
	fs.StringVar(&f.created, "created", "", "OpenPGP key creation time, RFC 3339 (part of the fingerprint: never change it)")
	fs.DurationVar(&f.lifetime, "lifetime", 0, "key validity from -created (0 = never expires)")
	fs.StringVar(&f.fingerprint, "fingerprint", "", "fail unless the derived key has this fingerprint (hex)")
}

func (f *identityFlags) entity(ctx context.Context, stderr io.Writer) (*openpgp.Entity, error) {
	if f.key == "" {
		return nil, errors.New("-key is required")
	}
	if f.created == "" {
		return nil, errors.New("-created is required (it is part of the fingerprint)")
	}
	created, err := time.Parse(time.RFC3339, f.created)
	if err != nil {
		return nil, fmt.Errorf("-created: %w", err)
	}
	signer, err := newSigner(ctx, f.key)
	if err != nil {
		return nil, err
	}
	e, err := gpgkms.NewEntity(signer, gpgkms.Identity{
		Name: f.name, Comment: f.comment, Email: f.email, Created: created, Lifetime: f.lifetime,
	})
	if err != nil {
		return nil, err
	}
	got := strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
	_, _ = fmt.Fprintf(stderr, "fingerprint: %s\n", got)
	if f.fingerprint != "" {
		want := strings.ToUpper(strings.ReplaceAll(f.fingerprint, " ", ""))
		if got != want {
			return nil, fmt.Errorf("derived key has fingerprint %s, want %s (wrong -key, -created or KMS key?)", got, want)
		}
	}
	return e, nil
}

func runPublicKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("public-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var id identityFlags
	id.register(fs)
	armored := fs.Bool("armor", true, "ASCII-armor the public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	e, err := id.entity(ctx, stderr)
	if err != nil {
		return err
	}
	return gpgkms.WritePublicKey(stdout, e, *armored)
}

func runSign(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var id identityFlags
	id.register(fs)
	armored := fs.Bool("armor", true, "write an ASCII-armored signature (.asc); -armor=false writes binary (.sig)")
	prependPath := fs.String("prepend", "", "binary detached signature whose packets are written before the KMS signature")
	outPath := fs.String("out", "", "path to write the detached signature to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("exactly one file to sign is required")
	}
	if *outPath == "" {
		return errors.New("-out is required")
	}

	var prepend []byte
	if *prependPath != "" {
		var err error
		prepend, err = os.ReadFile(*prependPath)
		if err != nil {
			return fmt.Errorf("read prepend signature: %w", err)
		}
	}

	e, err := id.entity(ctx, stderr)
	if err != nil {
		return err
	}

	message, err := os.Open(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("open file to sign: %w", err)
	}
	defer message.Close()

	var out bytes.Buffer
	if err := gpgkms.Sign(&out, e, message, gpgkms.SignOptions{Prepend: prepend, Armored: *armored}); err != nil {
		return err
	}
	// #nosec G306 -- detached signatures are public.
	if err := os.WriteFile(*outPath, out.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	return nil
}
