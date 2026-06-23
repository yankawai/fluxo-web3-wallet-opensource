package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func Encrypt(privateKey string, password string, address string) (Vault, error) {
	return encryptV2(privateKey, password, address, DefaultArgon2idParams(), ValidateProductionParams, time.Now)
}

func Decrypt(v Vault, password string) (UnlockResult, error) {
	return decryptV2(v, password, ValidateProductionParams)
}

func encryptV2(
	privateKey string,
	password string,
	address string,
	params Argon2idParams,
	validateKDF func(Argon2idParams) error,
	now func() time.Time,
) (Vault, error) {
	if strings.TrimSpace(privateKey) == "" {
		return Vault{}, fmt.Errorf("%w: missing private key", ErrInvalidVault)
	}
	if !isEthereumAddressShape(address) {
		return Vault{}, fmt.Errorf("%w: invalid address", ErrInvalidVault)
	}
	if validateKDF != nil {
		if err := validateKDF(params); err != nil {
			return Vault{}, err
		}
	}

	salt, err := randomBytes(params.SaltBytes)
	if err != nil {
		return Vault{}, err
	}
	nonce, err := randomBytes(NonceSize)
	if err != nil {
		return Vault{}, err
	}
	key, err := deriveKey(password, salt, params, validateKDF)
	if err != nil {
		return Vault{}, err
	}
	defer zeroBytes(key)

	header := Header{
		Version:   FormatVersion,
		Cipher:    CipherXChaCha20Poly1305,
		KDF:       KDFArgon2id,
		KDFParams: params,
		Address:   address,
		CreatedAt: now().UTC().Format(time.RFC3339Nano),
	}
	aad, err := aadForHeader(header)
	if err != nil {
		return Vault{}, err
	}

	ciphertext, err := seal(key, nonce, aad, Plaintext{PrivateKey: privateKey})
	if err != nil {
		return Vault{}, err
	}

	v := Vault{
		Header:     header,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	if err := validateVault(v, validateKDF); err != nil {
		return Vault{}, err
	}
	return v, nil
}

func decryptV2(v Vault, password string, validateKDF func(Argon2idParams) error) (UnlockResult, error) {
	if err := validateVault(v, validateKDF); err != nil {
		return UnlockResult{}, err
	}
	salt, err := base64.StdEncoding.DecodeString(v.Salt)
	if err != nil {
		return UnlockResult{}, fmt.Errorf("%w: invalid salt encoding", ErrInvalidVault)
	}
	nonce, err := base64.StdEncoding.DecodeString(v.Nonce)
	if err != nil {
		return UnlockResult{}, fmt.Errorf("%w: invalid nonce encoding", ErrInvalidVault)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(v.Ciphertext)
	if err != nil {
		return UnlockResult{}, fmt.Errorf("%w: invalid ciphertext encoding", ErrInvalidVault)
	}
	key, err := deriveKey(password, salt, v.Header.KDFParams, validateKDF)
	if err != nil {
		return UnlockResult{}, err
	}
	defer zeroBytes(key)

	aad, err := aadForHeader(v.Header)
	if err != nil {
		return UnlockResult{}, err
	}
	plaintext, err := open(key, nonce, aad, ciphertext)
	if err != nil {
		return UnlockResult{}, ErrInvalidPassword
	}
	if strings.TrimSpace(plaintext.PrivateKey) == "" {
		return UnlockResult{}, fmt.Errorf("%w: missing private key", ErrInvalidVault)
	}

	return UnlockResult{
		PrivateKey: plaintext.PrivateKey,
		Address:    v.Header.Address,
	}, nil
}

func seal(key []byte, nonce []byte, aad []byte, plaintext Plaintext) ([]byte, error) {
	payload, err := json.Marshal(plaintext)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, payload, aad), nil
}

func open(key []byte, nonce []byte, aad []byte, ciphertext []byte) (Plaintext, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Plaintext{}, err
	}
	payload, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return Plaintext{}, err
	}
	var plaintext Plaintext
	if err := json.Unmarshal(payload, &plaintext); err != nil {
		return Plaintext{}, fmt.Errorf("%w: invalid plaintext", ErrInvalidVault)
	}
	return plaintext, nil
}

func aadForHeader(header Header) ([]byte, error) {
	return json.Marshal(header)
}

func randomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}
