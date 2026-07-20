// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package keys holds the long-lived ed25519 identity both ends of SDB present,
// wrapped in a self-signed certificate so it can ride a stdlib TLS handshake.
//
// The certificate is only a carrier. Nothing trusts its issuer, its subject or
// its validity window: identity is the SHA-256 of the SubjectPublicKeyInfo, and
// that is what the keystore pins. Using a CA here would add a second thing to
// defend without adding anything the pin does not already give us.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity is one end's key pair plus the certificate that carries it.
type Identity struct {
	Cert tls.Certificate
	priv ed25519.PrivateKey
}

// Fingerprint is the SHA-256 of a SubjectPublicKeyInfo, the only identity SDB
// recognises.
func Fingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// FingerprintOf returns the fingerprint of a parsed certificate's public key.
func FingerprintOf(cert *x509.Certificate) string {
	return Fingerprint(cert.RawSubjectPublicKeyInfo)
}

// Display groups a fingerprint into short blocks so a human can compare what is
// on the device screen with what the host prints. The first blocks are the ones
// people actually read, so Display keeps the whole value rather than truncating
// it and inviting a prefix collision.
func Display(fp string) string {
	fp = strings.ToUpper(fp)
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := min(i+4, len(fp))
		b.WriteString(fp[i:end])
	}
	return b.String()
}

// Fingerprint returns this identity's own fingerprint.
func (id *Identity) Fingerprint() string {
	return Fingerprint(id.SPKI())
}

// SPKI returns the marshalled SubjectPublicKeyInfo of the public key.
func (id *Identity) SPKI() []byte {
	der, err := x509.MarshalPKIXPublicKey(id.priv.Public())
	if err != nil {
		return nil
	}
	return der
}

// LoadOrCreate returns the identity stored under dir, generating and persisting
// a fresh one the first time. A key file that exists but cannot be parsed is an
// error, never a silent regeneration: silently minting a new identity would
// revoke every pairing without telling anyone.
func LoadOrCreate(dir, name string) (*Identity, error) {
	keyPath := filepath.Join(dir, name+".key")
	certPath := filepath.Join(dir, name+".crt")

	keyPEM, keyErr := os.ReadFile(keyPath)
	certPEM, certErr := os.ReadFile(certPath)
	switch {
	case keyErr == nil && certErr == nil:
		return parse(keyPEM, certPEM)
	case errors.Is(keyErr, os.ErrNotExist) && errors.Is(certErr, os.ErrNotExist):
	case keyErr != nil:
		return nil, fmt.Errorf("read identity key: %w", keyErr)
	default:
		return nil, fmt.Errorf("read identity certificate: %w", certErr)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	keyPEM, certPEM, err := generate(name)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write identity key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write identity certificate: %w", err)
	}
	return parse(keyPEM, certPEM)
}

func generate(name string) (keyPEM, certPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate identity: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		// The window is deliberately long. Expiry is not a control here: trust
		// ends when the user revokes the key, not when a date passes.
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal identity key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return keyPEM, certPEM, nil
}

func parse(keyPEM, certPEM []byte) (*Identity, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("parse identity: not an ed25519 key")
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse identity certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return &Identity{Cert: cert, priv: priv}, nil
}
