package walletcore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const (
	privateKeySize = 32
)

var (
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrEmptyMessage      = errors.New("message is required")
)

type GeneratedWallet struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privateKey"`
}

type SignedMessage struct {
	Address   string `json:"address"`
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
}

func GenerateWallet() (GeneratedWallet, error) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return GeneratedWallet{}, err
	}

	privateKeyHex := hex.EncodeToString(privateKey.Serialize())
	address, err := AddressFromPrivateKey(privateKeyHex)
	if err != nil {
		return GeneratedWallet{}, err
	}

	return GeneratedWallet{
		Address:    address,
		PrivateKey: "0x" + privateKeyHex,
	}, nil
}

func AddressFromPrivateKey(privateKeyHex string) (string, error) {
	privateKey, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.PubKey().SerializeUncompressed()
	hash := keccak256(publicKey[1:])
	return checksumAddress(hex.EncodeToString(hash[12:])), nil
}

func SignMessage(privateKeyHex string, message string) (SignedMessage, error) {
	privateKey, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return SignedMessage{}, err
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return SignedMessage{}, ErrEmptyMessage
	}

	hash := EthereumMessageHash([]byte(message))
	compact := secpECDSA.SignCompact(privateKey, hash, false)
	if len(compact) != 65 {
		return SignedMessage{}, fmt.Errorf("unexpected compact signature length %d", len(compact))
	}

	recoveryID := compact[0] - 27
	signature := make([]byte, 65)
	copy(signature[:64], compact[1:])
	signature[64] = recoveryID + 27

	address, err := AddressFromPrivateKey(privateKeyHex)
	if err != nil {
		return SignedMessage{}, err
	}

	return SignedMessage{
		Address:   address,
		Hash:      "0x" + hex.EncodeToString(hash),
		Signature: "0x" + hex.EncodeToString(signature),
	}, nil
}

func EthereumMessageHash(message []byte) []byte {
	prefix := []byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message)))
	payload := make([]byte, 0, len(prefix)+len(message))
	payload = append(payload, prefix...)
	payload = append(payload, message...)
	return keccak256(payload)
}

func parsePrivateKey(privateKeyHex string) (*secp256k1.PrivateKey, error) {
	privateKeyHex = strings.TrimSpace(privateKeyHex)
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0X")
	if len(privateKeyHex) != privateKeySize*2 {
		return nil, ErrInvalidPrivateKey
	}

	bytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	if allZero(bytes) {
		return nil, ErrInvalidPrivateKey
	}

	privateKey := secp256k1.PrivKeyFromBytes(bytes)
	if privateKey.Key.IsZero() {
		return nil, ErrInvalidPrivateKey
	}

	return privateKey, nil
}

func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func checksumAddress(hexAddress string) string {
	lower := strings.ToLower(strings.TrimPrefix(hexAddress, "0x"))
	hash := hex.EncodeToString(keccak256([]byte(lower)))
	var builder strings.Builder
	builder.Grow(42)
	builder.WriteString("0x")

	for i, char := range lower {
		if char >= '0' && char <= '9' {
			builder.WriteRune(char)
			continue
		}
		if hash[i] >= '8' {
			builder.WriteString(strings.ToUpper(string(char)))
			continue
		}
		builder.WriteRune(char)
	}

	return builder.String()
}

func RandomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}
