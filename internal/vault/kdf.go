package vault

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

func deriveProductionKey(password string, salt []byte, params Argon2idParams) ([]byte, error) {
	return deriveKey(password, salt, params, ValidateProductionParams)
}

func deriveKey(
	password string,
	salt []byte,
	params Argon2idParams,
	validate func(Argon2idParams) error,
) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("%w: empty password", ErrInvalidPassword)
	}
	if len(salt) != params.SaltBytes {
		return nil, fmt.Errorf("%w: salt size mismatch", ErrInvalidVault)
	}
	if validate != nil {
		if err := validate(params); err != nil {
			return nil, err
		}
	}

	passwordBytes := []byte(password)
	defer zeroBytes(passwordBytes)

	return argon2.IDKey(
		passwordBytes,
		salt,
		params.Passes,
		params.MemoryKiB,
		params.Parallelism,
		params.KeyBytes,
	), nil
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
