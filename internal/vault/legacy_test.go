package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

func TestUnlockJSONMigratesV1Vault(t *testing.T) {
	rawV1 := testLegacyVault(t, testPrivateKey, testPassword, testAddress)
	result, err := unlockJSONWithPolicy(
		rawV1,
		testPassword,
		testArgon2idParams(),
		validateTestParams,
		func() time.Time { return time.Unix(1700000000, 0) },
	)
	if err != nil {
		t.Fatalf("unlockJSONWithPolicy() error = %v", err)
	}
	if result.PrivateKey != testPrivateKey || result.Address != testAddress {
		t.Fatalf("unexpected unlock result: %+v", result)
	}
	if result.MigratedVault == nil {
		t.Fatalf("MigratedVault is nil")
	}
	if result.MigratedVault.Header.Version != FormatVersion {
		t.Fatalf("migrated version = %d, want %d", result.MigratedVault.Header.Version, FormatVersion)
	}

	migrated, err := decryptV2(*result.MigratedVault, testPassword, validateTestParams)
	if err != nil {
		t.Fatalf("decrypt migrated vault: %v", err)
	}
	if migrated.PrivateKey != testPrivateKey {
		t.Fatalf("migrated private key mismatch")
	}
}

func TestUnlockJSONRejectsWrongV1Password(t *testing.T) {
	rawV1 := testLegacyVault(t, testPrivateKey, testPassword, testAddress)
	_, err := unlockJSONWithPolicy(rawV1, "wrong password", testArgon2idParams(), validateTestParams, time.Now)
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("unlockJSONWithPolicy() error = %v, want %v", err, ErrInvalidPassword)
	}
}

func TestUnlockJSONRejectsUnsupportedV1Params(t *testing.T) {
	var v legacyVault
	if err := json.Unmarshal([]byte(testLegacyVault(t, testPrivateKey, testPassword, testAddress)), &v); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	v.Iterations = 1000
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	_, err = unlockJSONWithPolicy(string(raw), testPassword, testArgon2idParams(), validateTestParams, time.Now)
	if !errors.Is(err, ErrUnsupportedV1) {
		t.Fatalf("unlockJSONWithPolicy() error = %v, want %v", err, ErrUnsupportedV1)
	}
}

func testLegacyVault(t *testing.T, privateKey string, password string, address string) string {
	t.Helper()
	salt := []byte("1234567890abcdef")
	nonce := []byte("123456789012")
	key := pbkdf2.Key([]byte(password), salt, legacyIterations, legacyAESGCMKeySize, sha256.New)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM() error = %v", err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte(privateKey), nil)
	v := legacyVault{
		Version:    legacyVersion,
		Address:    address,
		KDF:        legacyKDF,
		Iterations: legacyIterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		IV:         base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return string(raw)
}
