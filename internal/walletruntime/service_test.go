package walletruntime

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yankawai/go-web3-wallet/internal/vault"
)

const (
	testAddress    = "0x2F9cEFeC27bc129155FaA7a6cA033B25C5c36B06"
	testPrivateKey = "0x4c0883a69102937d6231471b5dbb6204fe512961708279d05a8f8bbd3c4f4d8f"
)

func TestServiceSignsThroughSession(t *testing.T) {
	service := newServiceWithTTL(time.Minute)
	session, err := service.openSession(testAddress, testPrivateKey)
	if err != nil {
		t.Fatalf("openSession() error = %v", err)
	}

	signed, err := service.SignMessage(session.SessionID, "hello")
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}
	if signed.Address != session.Address {
		t.Fatalf("signed address = %s, want %s", signed.Address, session.Address)
	}
	if signed.Signature == "" || signed.Hash == "" {
		t.Fatalf("signed message incomplete: %+v", signed)
	}
}

func TestServiceLockPreventsSigning(t *testing.T) {
	service := newServiceWithTTL(time.Minute)
	session, err := service.openSession(testAddress, testPrivateKey)
	if err != nil {
		t.Fatalf("openSession() error = %v", err)
	}
	service.Lock(session.SessionID)

	_, err = service.SignMessage(session.SessionID, "hello")
	if !errors.Is(err, vault.ErrSessionLocked) {
		t.Fatalf("SignMessage() error = %v, want %v", err, vault.ErrSessionLocked)
	}
}

func TestServiceRejectsAddressMismatch(t *testing.T) {
	service := newServiceWithTTL(time.Minute)
	_, err := service.openSession("0x1111111111111111111111111111111111111111", testPrivateKey)
	if !errors.Is(err, ErrAddressMismatch) {
		t.Fatalf("openSession() error = %v, want %v", err, ErrAddressMismatch)
	}
}

func TestServiceCreateVaultDoesNotReturnPrivateKey(t *testing.T) {
	service := newServiceWithVault(
		time.Minute,
		func(_ string, _ string, address string) (vault.Vault, error) {
			return vault.Vault{
				Header: vault.Header{
					Version: vault.FormatVersion,
					Address: address,
				},
				Ciphertext: "encrypted",
			}, nil
		},
		nil,
	)

	response, err := service.CreateVault("correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(raw), "privateKey") || strings.Contains(string(raw), testPrivateKey) {
		t.Fatalf("response leaked private key material: %s", string(raw))
	}
	if response.SessionID == "" || response.Address == "" {
		t.Fatalf("session response incomplete: %+v", response)
	}
}

func TestServiceUnlockVaultDoesNotReturnPrivateKey(t *testing.T) {
	service := newServiceWithVault(
		time.Minute,
		nil,
		func(_ vault.Vault, _ string) (vault.UnlockResult, error) {
			return vault.UnlockResult{
				PrivateKey: testPrivateKey,
				Address:    testAddress,
			}, nil
		},
	)
	rawVault := `{"header":{"version":2,"address":"` + testAddress + `"},"ciphertext":"encrypted"}`

	response, err := service.UnlockVault(rawVault, "correct horse battery staple")
	if err != nil {
		t.Fatalf("UnlockVault() error = %v", err)
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(raw), "privateKey") || strings.Contains(string(raw), testPrivateKey) {
		t.Fatalf("response leaked private key material: %s", string(raw))
	}
}
