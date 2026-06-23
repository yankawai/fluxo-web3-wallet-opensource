package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	LegacyV2FormatVersion = 2
	FormatVersion         = 3

	CipherXChaCha20Poly1305 = "XCHACHA20-POLY1305"
	KDFArgon2id             = "ARGON2ID"
	VaultKindHDMnemonic     = "hd-mnemonic"
	VaultKindPrivateKey     = "private-key"

	SaltSize  = 32
	NonceSize = 24
	KeySize   = 32
)

var (
	ErrInvalidVault    = errors.New("invalid vault")
	ErrUnsupportedKDF  = errors.New("unsupported vault kdf")
	ErrWeakKDF         = errors.New("vault kdf parameters are below policy")
	ErrUnsupportedV1   = errors.New("unsupported v1 vault")
	ErrInvalidPassword = errors.New("invalid vault password")
)

type Argon2idParams struct {
	MemoryKiB   uint32 `json:"memoryKiB"`
	Passes      uint32 `json:"passes"`
	Parallelism uint8  `json:"parallelism"`
	SaltBytes   int    `json:"saltBytes"`
	KeyBytes    uint32 `json:"keyBytes"`
}

type Header struct {
	Version   int            `json:"version"`
	Cipher    string         `json:"cipher"`
	KDF       string         `json:"kdf"`
	KDFParams Argon2idParams `json:"kdfParams"`
	Kind      string         `json:"kind"`
	Address   string         `json:"address"`
	CreatedAt string         `json:"createdAt"`
}

type Vault struct {
	Header     Header `json:"header"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Plaintext struct {
	PrivateKey         string `json:"privateKey,omitempty"`
	Mnemonic           string `json:"mnemonic,omitempty"`
	ActiveAccountIndex uint32 `json:"activeAccountIndex,omitempty"`
}

type UnlockResult struct {
	PrivateKey         string
	Mnemonic           string
	ActiveAccountIndex uint32
	Address            string
	Kind               string
	MigratedVault      *Vault
}

func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		MemoryKiB:   256 * 1024,
		Passes:      4,
		Parallelism: 1,
		SaltBytes:   SaltSize,
		KeyBytes:    KeySize,
	}
}

func (v Vault) Validate() error {
	return validateVault(v, ValidateProductionParams)
}

func validateVault(v Vault, validateKDF func(Argon2idParams) error) error {
	if v.Header.Version != FormatVersion && v.Header.Version != LegacyV2FormatVersion {
		return fmt.Errorf("%w: version %d", ErrInvalidVault, v.Header.Version)
	}
	if v.Header.Version == FormatVersion && v.Header.Kind != VaultKindHDMnemonic {
		return fmt.Errorf("%w: vault kind %q", ErrInvalidVault, v.Header.Kind)
	}
	if v.Header.Version == LegacyV2FormatVersion && v.Header.Kind != "" && v.Header.Kind != VaultKindPrivateKey {
		return fmt.Errorf("%w: vault kind %q", ErrInvalidVault, v.Header.Kind)
	}
	if v.Header.Cipher != CipherXChaCha20Poly1305 {
		return fmt.Errorf("%w: cipher %q", ErrInvalidVault, v.Header.Cipher)
	}
	if v.Header.KDF != KDFArgon2id {
		return fmt.Errorf("%w: %q", ErrUnsupportedKDF, v.Header.KDF)
	}
	if validateKDF != nil {
		if err := validateKDF(v.Header.KDFParams); err != nil {
			return err
		}
	}
	if !isEthereumAddressShape(v.Header.Address) {
		return fmt.Errorf("%w: invalid address metadata", ErrInvalidVault)
	}
	if strings.TrimSpace(v.Header.CreatedAt) == "" {
		return fmt.Errorf("%w: missing creation time", ErrInvalidVault)
	}
	if err := validateBase64Size(v.Salt, SaltSize, "salt"); err != nil {
		return err
	}
	if err := validateBase64Size(v.Nonce, NonceSize, "nonce"); err != nil {
		return err
	}
	if strings.TrimSpace(v.Ciphertext) == "" {
		return fmt.Errorf("%w: missing ciphertext", ErrInvalidVault)
	}
	if _, err := base64.StdEncoding.DecodeString(v.Ciphertext); err != nil {
		return fmt.Errorf("%w: invalid ciphertext encoding", ErrInvalidVault)
	}
	return nil
}

func ValidateProductionParams(params Argon2idParams) error {
	defaults := DefaultArgon2idParams()
	if params.KDFSizeMismatch(defaults) {
		return fmt.Errorf("%w: invalid salt or key size", ErrInvalidVault)
	}
	if params.MemoryKiB < defaults.MemoryKiB ||
		params.Passes < defaults.Passes ||
		params.Parallelism != defaults.Parallelism {
		return ErrWeakKDF
	}
	return nil
}

func (p Argon2idParams) KDFSizeMismatch(other Argon2idParams) bool {
	return p.SaltBytes != other.SaltBytes || p.KeyBytes != other.KeyBytes
}

func validateBase64Size(value string, size int, field string) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%w: invalid %s encoding", ErrInvalidVault, field)
	}
	if len(raw) != size {
		return fmt.Errorf("%w: %s has %d bytes", ErrInvalidVault, field, len(raw))
	}
	return nil
}

func isEthereumAddressShape(address string) bool {
	if len(address) != 42 || !strings.HasPrefix(address, "0x") {
		return false
	}
	for _, char := range address[2:] {
		if (char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'f') ||
			(char >= 'A' && char <= 'F') {
			continue
		}
		return false
	}
	return true
}
