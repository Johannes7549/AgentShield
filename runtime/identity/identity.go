// Package identity implements the AgentShield v1 request signature.
//
// Sign is for agent SDKs. The gateway calls Verify and stores only the public
// key. This package does not record nonces. A signature that verifies can
// still be replayed until the gateway stores the nonce, so Verify alone is
// not an authentication system.
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"time"
)

const (
	HeaderAgentID   = "X-AgentShield-Agent-Id"
	HeaderTimestamp = "X-AgentShield-Timestamp"
	HeaderNonce     = "X-AgentShield-Nonce"
	HeaderSignature = "X-AgentShield-Signature"

	// MaxClockSkew is the accepted difference between the signed timestamp
	// and the gateway clock. Replay handling inside this window is separate.
	MaxClockSkew = 60 * time.Second
)

var (
	ErrClockSkew    = errors.New("timestamp outside allowed skew")
	ErrBadSignature = errors.New("signature verification failed")
	ErrBadNonce     = errors.New("nonce is invalid")

	noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// SigningInput is the exact UTF-8 string covered by the Ed25519 signature.
// nonce cannot contain '.' because that character is the field separator.
// body is hashed as received. Callers must not re-serialize it first.
func SigningInput(timestamp int64, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return strconv.FormatInt(timestamp, 10) + "." + nonce + "." + hex.EncodeToString(sum[:])
}

// Fingerprint is the lowercase hex SHA-256 of the raw 32-byte public key.
func Fingerprint(public ed25519.PublicKey) (string, error) {
	if len(public) != ed25519.PublicKeySize {
		return "", errors.New("public key must be 32 bytes")
	}
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:]), nil
}

// Sign returns the unpadded base64url Ed25519 signature of SigningInput.
func Sign(private ed25519.PrivateKey, timestamp int64, nonce string, body []byte) (string, error) {
	if len(private) != ed25519.PrivateKeySize {
		return "", errors.New("private key must be 64 bytes")
	}
	if !noncePattern.MatchString(nonce) {
		return "", ErrBadNonce
	}
	signature := ed25519.Sign(private, []byte(SigningInput(timestamp, nonce, body)))
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

// Verify checks the signature, the nonce shape, and the timestamp window.
// now is supplied by the caller so tests can control the clock.
func Verify(public ed25519.PublicKey, timestamp int64, nonce string, body []byte, signature string, now time.Time) error {
	if len(public) != ed25519.PublicKeySize {
		return errors.New("public key must be 32 bytes")
	}
	if !noncePattern.MatchString(nonce) {
		return ErrBadNonce
	}
	if now.IsZero() {
		return errors.New("current time is required")
	}
	delta := now.Sub(time.Unix(timestamp, 0))
	if delta < -MaxClockSkew || delta > MaxClockSkew {
		return ErrClockSkew
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return ErrBadSignature
	}
	if !ed25519.Verify(public, []byte(SigningInput(timestamp, nonce, body)), raw) {
		return ErrBadSignature
	}
	return nil
}
