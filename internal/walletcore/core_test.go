package walletcore

import (
	"errors"
	"strings"
	"testing"
)

const testPrivateKey = "0x4c0883a69102937d6231471b5dbb6204fe512961708279d05a8f8bbd3c4f4d8f"

func TestGenerateWallet(t *testing.T) {
	wallet, err := GenerateWallet()
	if err != nil {
		t.Fatalf("GenerateWallet() error = %v", err)
	}
	if !strings.HasPrefix(wallet.Address, "0x") || len(wallet.Address) != 42 {
		t.Fatalf("address = %q, want Ethereum address", wallet.Address)
	}
	if !strings.HasPrefix(wallet.PrivateKey, "0x") || len(wallet.PrivateKey) != 66 {
		t.Fatalf("private key has unexpected shape")
	}
}

func TestAddressFromPrivateKey(t *testing.T) {
	address, err := AddressFromPrivateKey(testPrivateKey)
	if err != nil {
		t.Fatalf("AddressFromPrivateKey() error = %v", err)
	}
	if strings.ToLower(address) != "0x2f9cefec27bc129155faa7a6ca033b25c5c36b06" {
		t.Fatalf("address = %s", address)
	}
	if address == strings.ToLower(address) {
		t.Fatalf("address = %s, want checksum formatting", address)
	}
}

func TestSignMessage(t *testing.T) {
	signed, err := SignMessage(testPrivateKey, "hello")
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}
	if len(signed.Signature) != 132 {
		t.Fatalf("signature length = %d, want 132", len(signed.Signature))
	}
	if signed.Hash == "" || signed.Address == "" {
		t.Fatalf("signed message incomplete: %+v", signed)
	}
}

func TestSignMessageRejectsEmptyMessage(t *testing.T) {
	_, err := SignMessage(testPrivateKey, " ")
	if !errors.Is(err, ErrEmptyMessage) {
		t.Fatalf("SignMessage() error = %v, want %v", err, ErrEmptyMessage)
	}
}

func TestAddressRejectsInvalidPrivateKey(t *testing.T) {
	_, err := AddressFromPrivateKey("0x00")
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("AddressFromPrivateKey() error = %v, want %v", err, ErrInvalidPrivateKey)
	}
}
