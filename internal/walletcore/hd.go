package walletcore

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

const (
	DefaultMnemonicEntropyBits = 128
	EthereumCoinType           = uint32(60)
)

type HDAccount struct {
	Index   uint32 `json:"index"`
	Path    string `json:"path"`
	Address string `json:"address"`
}

func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(DefaultMnemonicEntropyBits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func ValidateMnemonic(mnemonic string) error {
	if !bip39.IsMnemonicValid(normalizeMnemonic(mnemonic)) {
		return fmt.Errorf("%w: invalid mnemonic", ErrInvalidPrivateKey)
	}
	return nil
}

func DeriveAccount(mnemonic string, index uint32) (HDAccount, error) {
	privateKey, err := DerivePrivateKey(mnemonic, index)
	if err != nil {
		return HDAccount{}, err
	}
	address, err := AddressFromPrivateKey(privateKey)
	if err != nil {
		return HDAccount{}, err
	}
	return HDAccount{
		Index:   index,
		Path:    EthereumDerivationPath(index),
		Address: address,
	}, nil
}

func DerivePrivateKey(mnemonic string, index uint32) (string, error) {
	mnemonic = normalizeMnemonic(mnemonic)
	if err := ValidateMnemonic(mnemonic); err != nil {
		return "", err
	}
	seed := bip39.NewSeed(mnemonic, "")
	defer zeroBytes(seed)

	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return "", err
	}
	for _, child := range []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + EthereumCoinType,
		bip32.FirstHardenedChild,
		0,
		index,
	} {
		key, err = key.NewChildKey(child)
		if err != nil {
			return "", err
		}
	}
	if !key.IsPrivate || len(key.Key) != privateKeySize {
		return "", ErrInvalidPrivateKey
	}
	return "0x" + hex.EncodeToString(key.Key), nil
}

func EthereumDerivationPath(index uint32) string {
	return fmt.Sprintf("m/44'/60'/0'/0/%d", index)
}

func normalizeMnemonic(mnemonic string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(mnemonic))), " ")
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
