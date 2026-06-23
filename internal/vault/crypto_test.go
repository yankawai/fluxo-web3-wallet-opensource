package vault

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

const (
	testAddress    = "0x2F9cEFeC27bc129155FaA7a6cA033B25C5c36B06"
	testPrivateKey = "0x4c0883a69102937d6231471b5dbb6204fe512961708279d05a8f8bbd3c4f4d8f"
	testPassword   = "correct horse battery staple"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	v := testEncryptVault(t, testPrivateKey, testPassword, testAddress)
	result, err := decryptV2(v, testPassword, validateTestParams)
	if err != nil {
		t.Fatalf("decryptV2() error = %v", err)
	}
	if result.PrivateKey != testPrivateKey {
		t.Fatalf("private key mismatch")
	}
	if result.Address != testAddress {
		t.Fatalf("address = %s, want %s", result.Address, testAddress)
	}
}

func TestDecryptRejectsWrongPassword(t *testing.T) {
	v := testEncryptVault(t, testPrivateKey, testPassword, testAddress)
	_, err := decryptV2(v, "wrong password", validateTestParams)
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("decryptV2() error = %v, want %v", err, ErrInvalidPassword)
	}
}

func TestEncryptUsesUniqueNonce(t *testing.T) {
	first := testEncryptVault(t, testPrivateKey, testPassword, testAddress)
	second := testEncryptVault(t, testPrivateKey, testPassword, testAddress)
	if first.Nonce == second.Nonce {
		t.Fatalf("nonces matched: %s", first.Nonce)
	}
	if _, err := base64.StdEncoding.DecodeString(first.Nonce); err != nil {
		t.Fatalf("nonce is not base64: %v", err)
	}
}

func testEncryptVault(t *testing.T, privateKey string, password string, address string) Vault {
	t.Helper()
	v, err := encryptV2(
		privateKey,
		password,
		address,
		testArgon2idParams(),
		validateTestParams,
		func() time.Time { return time.Unix(1700000000, 0) },
	)
	if err != nil {
		t.Fatalf("encryptV2() error = %v", err)
	}
	return v
}
