package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestDefaultArgon2idParams(t *testing.T) {
	params := DefaultArgon2idParams()
	if params.MemoryKiB != 256*1024 {
		t.Fatalf("MemoryKiB = %d, want 262144", params.MemoryKiB)
	}
	if params.Passes != 4 {
		t.Fatalf("Passes = %d, want 4", params.Passes)
	}
	if params.Parallelism != 1 {
		t.Fatalf("Parallelism = %d, want 1", params.Parallelism)
	}
	if params.SaltBytes != 32 || params.KeyBytes != 32 {
		t.Fatalf("salt/key sizes = %d/%d, want 32/32", params.SaltBytes, params.KeyBytes)
	}
}

func TestValidateProductionParamsRejectsDowngrade(t *testing.T) {
	tests := map[string]Argon2idParams{
		"memory": {
			MemoryKiB:   64 * 1024,
			Passes:      4,
			Parallelism: 1,
			SaltBytes:   32,
			KeyBytes:    32,
		},
		"passes": {
			MemoryKiB:   256 * 1024,
			Passes:      2,
			Parallelism: 1,
			SaltBytes:   32,
			KeyBytes:    32,
		},
		"parallelism": {
			MemoryKiB:   256 * 1024,
			Passes:      4,
			Parallelism: 2,
			SaltBytes:   32,
			KeyBytes:    32,
		},
	}

	for name, params := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateProductionParams(params); !errors.Is(err, ErrWeakKDF) {
				t.Fatalf("ValidateProductionParams() error = %v, want %v", err, ErrWeakKDF)
			}
		})
	}
}

func TestValidateProductionParamsRejectsSizeMismatch(t *testing.T) {
	params := DefaultArgon2idParams()
	params.SaltBytes = 16
	if err := ValidateProductionParams(params); !errors.Is(err, ErrInvalidVault) {
		t.Fatalf("ValidateProductionParams() error = %v, want %v", err, ErrInvalidVault)
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	params := testArgon2idParams()
	salt := bytes.Repeat([]byte{1}, params.SaltBytes)
	first, err := deriveKey("correct horse battery", salt, params, validateTestParams)
	if err != nil {
		t.Fatalf("deriveKey() error = %v", err)
	}
	second, err := deriveKey("correct horse battery", salt, params, validateTestParams)
	if err != nil {
		t.Fatalf("deriveKey() error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("derived keys differ for same inputs")
	}
	if len(first) != int(params.KeyBytes) {
		t.Fatalf("key length = %d, want %d", len(first), params.KeyBytes)
	}
}

func TestDeriveKeyRejectsEmptyPassword(t *testing.T) {
	params := testArgon2idParams()
	salt := bytes.Repeat([]byte{1}, params.SaltBytes)
	if _, err := deriveKey("", salt, params, validateTestParams); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("deriveKey() error = %v, want %v", err, ErrInvalidPassword)
	}
}

func testArgon2idParams() Argon2idParams {
	return Argon2idParams{
		MemoryKiB:   64,
		Passes:      1,
		Parallelism: 1,
		SaltBytes:   SaltSize,
		KeyBytes:    KeySize,
	}
}

func validateTestParams(params Argon2idParams) error {
	expected := testArgon2idParams()
	if params.KDFSizeMismatch(expected) {
		return ErrInvalidVault
	}
	if params.MemoryKiB < expected.MemoryKiB ||
		params.Passes < expected.Passes ||
		params.Parallelism != expected.Parallelism {
		return ErrWeakKDF
	}
	return nil
}
