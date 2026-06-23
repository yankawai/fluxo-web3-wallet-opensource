package walletcore

import (
	"strings"
	"testing"
)

const testMnemonic = "test test test test test test test test test test test junk"

func TestGenerateMnemonic(t *testing.T) {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic() error = %v", err)
	}
	if words := strings.Fields(mnemonic); len(words) != 12 {
		t.Fatalf("word count = %d, want 12", len(words))
	}
	if err := ValidateMnemonic(mnemonic); err != nil {
		t.Fatalf("generated mnemonic invalid: %v", err)
	}
}

func TestDeriveAccount(t *testing.T) {
	account, err := DeriveAccount(testMnemonic, 0)
	if err != nil {
		t.Fatalf("DeriveAccount() error = %v", err)
	}
	if account.Path != "m/44'/60'/0'/0/0" {
		t.Fatalf("path = %s", account.Path)
	}
	if strings.ToLower(account.Address) != "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" {
		t.Fatalf("address = %s", account.Address)
	}
}

func TestDeriveAccountsUseDistinctAddresses(t *testing.T) {
	first, err := DeriveAccount(testMnemonic, 0)
	if err != nil {
		t.Fatalf("DeriveAccount(0) error = %v", err)
	}
	second, err := DeriveAccount(testMnemonic, 1)
	if err != nil {
		t.Fatalf("DeriveAccount(1) error = %v", err)
	}
	if first.Address == second.Address {
		t.Fatalf("derived duplicate address %s", first.Address)
	}
}

func TestValidateMnemonicRejectsInvalidPhrase(t *testing.T) {
	if err := ValidateMnemonic("not a real wallet phrase"); err == nil {
		t.Fatalf("ValidateMnemonic() expected error")
	}
}
