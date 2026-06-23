package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	legacyVersion       = 1
	legacyKDF           = "PBKDF2-SHA256"
	legacyIterations    = 250000
	legacySaltSize      = 16
	legacyNonceSize     = 12
	legacyAESGCMKeySize = 32
)

type legacyVault struct {
	Version    int    `json:"version"`
	Address    string `json:"address"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

func UnlockJSON(rawVault string, password string) (UnlockResult, error) {
	return unlockJSONWithPolicy(rawVault, password, DefaultArgon2idParams(), ValidateProductionParams, time.Now)
}

func unlockJSONWithPolicy(
	rawVault string,
	password string,
	params Argon2idParams,
	validateKDF func(Argon2idParams) error,
	now func() time.Time,
) (UnlockResult, error) {
	format, err := detectVaultFormat(rawVault)
	if err != nil {
		return UnlockResult{}, err
	}
	switch format {
	case FormatVersion:
		var v Vault
		if err := json.Unmarshal([]byte(rawVault), &v); err != nil {
			return UnlockResult{}, fmt.Errorf("%w: invalid v2 vault json", ErrInvalidVault)
		}
		return decryptV2(v, password, validateKDF)
	case legacyVersion:
		var v legacyVault
		if err := json.Unmarshal([]byte(rawVault), &v); err != nil {
			return UnlockResult{}, fmt.Errorf("%w: invalid v1 vault json", ErrInvalidVault)
		}
		result, err := decryptLegacyV1(v, password)
		if err != nil {
			return UnlockResult{}, err
		}
		migrated, err := encryptV2(result.PrivateKey, password, result.Address, params, validateKDF, now)
		if err != nil {
			return UnlockResult{}, err
		}
		result.MigratedVault = &migrated
		return result, nil
	default:
		return UnlockResult{}, fmt.Errorf("%w: version %d", ErrInvalidVault, format)
	}
}

func detectVaultFormat(rawVault string) (int, error) {
	var probe struct {
		Header *struct {
			Version int `json:"version"`
		} `json:"header"`
		Version int `json:"version"`
	}
	if err := json.Unmarshal([]byte(rawVault), &probe); err != nil {
		return 0, fmt.Errorf("%w: invalid vault json", ErrInvalidVault)
	}
	if probe.Header != nil {
		return probe.Header.Version, nil
	}
	return probe.Version, nil
}

func decryptLegacyV1(v legacyVault, password string) (UnlockResult, error) {
	if v.Version != legacyVersion ||
		v.KDF != legacyKDF ||
		v.Iterations != legacyIterations ||
		!isEthereumAddressShape(v.Address) {
		return UnlockResult{}, ErrUnsupportedV1
	}
	salt, err := decodeLegacyField(v.Salt, legacySaltSize, "salt")
	if err != nil {
		return UnlockResult{}, err
	}
	nonce, err := decodeLegacyField(v.IV, legacyNonceSize, "iv")
	if err != nil {
		return UnlockResult{}, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(v.Ciphertext)
	if err != nil {
		return UnlockResult{}, fmt.Errorf("%w: invalid v1 ciphertext", ErrInvalidVault)
	}

	passwordBytes := []byte(password)
	defer zeroBytes(passwordBytes)
	key := pbkdf2.Key(passwordBytes, salt, v.Iterations, legacyAESGCMKeySize, sha256.New)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return UnlockResult{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return UnlockResult{}, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return UnlockResult{}, ErrInvalidPassword
	}

	return UnlockResult{
		PrivateKey: string(plaintext),
		Address:    v.Address,
	}, nil
}

func decodeLegacyField(value string, size int, field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid v1 %s", ErrInvalidVault, field)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%w: invalid v1 %s size", ErrInvalidVault, field)
	}
	return raw, nil
}
