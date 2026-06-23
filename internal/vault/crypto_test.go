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
	testMnemonic   = "test test test test test test test test test test test junk"
	testPassword   = "correct horse battery staple"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	v := testEncryptVault(t, testMnemonic, testPassword, testAddress)
	result, err := decryptVault(v, testPassword, validateTestParams)
	if err != nil {
		t.Fatalf("decryptVault() error = %v", err)
	}
	if result.Mnemonic != testMnemonic {
		t.Fatalf("mnemonic mismatch")
	}
	if result.Address != testAddress {
		t.Fatalf("address = %s, want %s", result.Address, testAddress)
	}
	if result.Kind != VaultKindHDMnemonic {
		t.Fatalf("kind = %s, want %s", result.Kind, VaultKindHDMnemonic)
	}
}

func TestDecryptRejectsWrongPassword(t *testing.T) {
	v := testEncryptVault(t, testMnemonic, testPassword, testAddress)
	_, err := decryptVault(v, "wrong password", validateTestParams)
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("decryptVault() error = %v, want %v", err, ErrInvalidPassword)
	}
}

func TestEncryptUsesUniqueNonce(t *testing.T) {
	first := testEncryptVault(t, testMnemonic, testPassword, testAddress)
	second := testEncryptVault(t, testMnemonic, testPassword, testAddress)
	if first.Nonce == second.Nonce {
		t.Fatalf("nonces matched: %s", first.Nonce)
	}
	if _, err := base64.StdEncoding.DecodeString(first.Nonce); err != nil {
		t.Fatalf("nonce is not base64: %v", err)
	}
}

func TestDecryptRejectsMetadataTampering(t *testing.T) {
	v := testEncryptVault(t, testMnemonic, testPassword, testAddress)
	v.Header.Address = "0x1111111111111111111111111111111111111111"
	_, err := decryptVault(v, testPassword, validateTestParams)
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("decryptVault() error = %v, want %v", err, ErrInvalidPassword)
	}
}

func TestDecryptRejectsCiphertextTampering(t *testing.T) {
	v := testEncryptVault(t, testMnemonic, testPassword, testAddress)
	raw, err := base64.StdEncoding.DecodeString(v.Ciphertext)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	v.Ciphertext = base64.StdEncoding.EncodeToString(raw)

	_, err = decryptVault(v, testPassword, validateTestParams)
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("decryptVault() error = %v, want %v", err, ErrInvalidPassword)
	}
}

func TestDecryptRejectsKDFDowngrade(t *testing.T) {
	v := testEncryptVault(t, testMnemonic, testPassword, testAddress)
	v.Header.KDFParams.MemoryKiB = 1
	_, err := decryptVault(v, testPassword, validateTestParams)
	if !errors.Is(err, ErrWeakKDF) {
		t.Fatalf("decryptVault() error = %v, want %v", err, ErrWeakKDF)
	}
}

func TestDecryptLegacyV2PrivateKeyVault(t *testing.T) {
	v, err := encryptPrivateKeyV2(
		testPrivateKey,
		testPassword,
		testAddress,
		testArgon2idParams(),
		validateTestParams,
		func() time.Time { return time.Unix(1700000000, 0) },
	)
	if err != nil {
		t.Fatalf("encryptPrivateKeyV2() error = %v", err)
	}
	if v.Header.Version != LegacyV2FormatVersion {
		t.Fatalf("version = %d, want %d", v.Header.Version, LegacyV2FormatVersion)
	}
	result, err := decryptVault(v, testPassword, validateTestParams)
	if err != nil {
		t.Fatalf("decryptVault() error = %v", err)
	}
	if result.PrivateKey != testPrivateKey {
		t.Fatalf("private key mismatch")
	}
	if result.Kind != VaultKindPrivateKey {
		t.Fatalf("kind = %s, want %s", result.Kind, VaultKindPrivateKey)
	}
}

func testEncryptVault(t *testing.T, mnemonic string, password string, address string) Vault {
	t.Helper()
	v, err := encryptMnemonicV3(
		mnemonic,
		password,
		address,
		0,
		testArgon2idParams(),
		validateTestParams,
		func() time.Time { return time.Unix(1700000000, 0) },
	)
	if err != nil {
		t.Fatalf("encryptMnemonicV3() error = %v", err)
	}
	return v
}
