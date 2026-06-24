package vault

import (
	"encoding/base64"
	"testing"
	"time"
)

func FuzzDecryptRejectsVaultTampering(f *testing.F) {
	base, err := encryptMnemonicV3(
		testMnemonic,
		testPassword,
		testAddress,
		0,
		testArgon2idParams(),
		validateTestParams,
		func() time.Time { return time.Unix(1700000000, 0) },
	)
	if err != nil {
		f.Fatalf("encryptMnemonicV3() error = %v", err)
	}

	f.Add("address", byte(0x01))
	f.Add("ciphertext", byte(0x02))
	f.Add("kdf-memory", byte(0x03))
	f.Add("nonce", byte(0x04))
	f.Add("salt", byte(0x05))
	f.Add("version", byte(0x06))

	f.Fuzz(func(t *testing.T, field string, mask byte) {
		v := base
		switch field {
		case "address":
			v.Header.Address = "0x1111111111111111111111111111111111111111"
		case "ciphertext":
			v.Ciphertext = mutateBase64ForFuzz(t, v.Ciphertext, mask)
		case "kdf-memory":
			v.Header.KDFParams.MemoryKiB = 1
		case "nonce":
			v.Nonce = mutateBase64ForFuzz(t, v.Nonce, mask)
		case "salt":
			v.Salt = mutateBase64ForFuzz(t, v.Salt, mask)
		case "version":
			v.Header.Version++
		default:
			return
		}

		if _, err := decryptVault(v, testPassword, validateTestParams); err == nil {
			t.Fatalf("decryptVault() accepted tampered %q field", field)
		}
	})
}

func mutateBase64ForFuzz(t *testing.T, encoded string, mask byte) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("empty decoded input")
	}
	if mask == 0 {
		mask = 1
	}
	raw[len(raw)-1] ^= mask
	return base64.StdEncoding.EncodeToString(raw)
}
