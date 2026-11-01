package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	return public, private
}

func TestSigningInputBindsBodyBytes(t *testing.T) {
	body := []byte(`{"tool":"tickets.read"}`)
	got := SigningInput(1_700_000_000, "nonce-value-123456", body)
	if !strings.HasPrefix(got, "1700000000.nonce-value-123456.") {
		t.Fatalf("signing input = %q", got)
	}
	other := SigningInput(1_700_000_000, "nonce-value-123456", []byte(`{"tool":"tickets.write"}`))
	if got == other {
		t.Fatal("different bodies produced the same signing input")
	}
}

func TestSignAndVerify(t *testing.T) {
	public, private := testKey(t)
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"arguments":{"id":"t-1"}}`)
	signature, err := Sign(private, now.Unix(), "nonce-value-123456", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(public, now.Unix(), "nonce-value-123456", body, signature, now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	public, private := testKey(t)
	now := time.Unix(1_700_000_000, 0)
	signature, err := Sign(private, now.Unix(), "nonce-value-123456", []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(public, now.Unix(), "nonce-value-123456", []byte("changed"), signature, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyRejectsOtherKey(t *testing.T) {
	_, private := testKey(t)
	otherPublic, _ := testKey(t)
	otherPublic[0] ^= 0xff
	now := time.Unix(1_700_000_000, 0)
	signature, err := Sign(private, now.Unix(), "nonce-value-123456", []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(otherPublic, now.Unix(), "nonce-value-123456", []byte("body"), signature, now)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyClockSkew(t *testing.T) {
	public, private := testKey(t)
	now := time.Unix(1_700_000_000, 0)
	body := []byte("body")
	signature, err := Sign(private, now.Add(MaxClockSkew).Unix(), "nonce-value-123456", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(public, now.Add(MaxClockSkew).Unix(), "nonce-value-123456", body, signature, now); err != nil {
		t.Fatal(err)
	}
	late := now.Add(MaxClockSkew + time.Second).Unix()
	signature, err = Sign(private, late, "nonce-value-123456", body)
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(public, late, "nonce-value-123456", body, signature, now)
	if !errors.Is(err, ErrClockSkew) {
		t.Fatalf("error = %v", err)
	}
}

func TestNonceShape(t *testing.T) {
	_, private := testKey(t)
	if _, err := Sign(private, 1, "short", []byte("body")); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("error = %v", err)
	}
	if _, err := Sign(private, 1, "nonce.with.dots.present", []byte("body")); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("error = %v", err)
	}
}

func TestSDKVector(t *testing.T) {
	public, private := testKey(t)
	body := []byte(`{"tool":"tickets.read"}`)
	const wantInput = "1700000000.nonce-value-123456.c64754e077ed2605c1a851045e3a42681df935f7482c6819446c8744f857cc28"
	if got := SigningInput(1_700_000_000, "nonce-value-123456", body); got != wantInput {
		t.Fatalf("signing input = %s", got)
	}
	signature, err := Sign(private, 1_700_000_000, "nonce-value-123456", body)
	if err != nil {
		t.Fatal(err)
	}
	const wantSignature = "fuxPrL6xKqaUrNI4eHSNfcIoPltHnPttEXvZdJL_tG2kYJ8L1Sy90OJNWpWczTkYrN9-y_oP9sCeloHIF2zoBA"
	if signature != wantSignature {
		t.Fatalf("signature = %s", signature)
	}
	if got := base64.RawURLEncoding.EncodeToString(public); got != "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI" {
		t.Fatalf("public key = %s", got)
	}
}

func TestFingerprint(t *testing.T) {
	public, _ := testKey(t)
	first, err := Fingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 {
		t.Fatalf("fingerprint length = %d", len(first))
	}
	public[0] ^= 0x01
	second, err := Fingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("distinct keys produced the same fingerprint")
	}
}
