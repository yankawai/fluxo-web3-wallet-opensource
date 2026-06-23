package secureelement

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testMnemonic = "test test test test test test test test test test test junk"

func TestSoftwareElementProvisionDeriveAndSign(t *testing.T) {
	element := newTestElement()
	ctx := context.Background()

	info, err := element.ProvisionMnemonic(ctx, "primary", testMnemonic, DefaultPolicy())
	if err != nil {
		t.Fatalf("ProvisionMnemonic() error = %v", err)
	}
	if info.Address != "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" {
		t.Fatalf("address = %s", info.Address)
	}
	if info.Path != "m/44'/60'/0'/0/0" {
		t.Fatalf("path = %s", info.Path)
	}

	account, err := element.DeriveAddress(ctx, "primary", 0)
	if err != nil {
		t.Fatalf("DeriveAddress() error = %v", err)
	}
	if account.Address != info.Address {
		t.Fatalf("derived address = %s, want %s", account.Address, info.Address)
	}

	signed, err := element.SignEIP191Message(ctx, "primary", 0, "hello fluxo", Authorization{UserPresence: true})
	if err != nil {
		t.Fatalf("SignEIP191Message() error = %v", err)
	}
	if signed.Address != info.Address {
		t.Fatalf("signed address = %s, want %s", signed.Address, info.Address)
	}
	if signed.Hash == "" || signed.Signature == "" {
		t.Fatalf("signed message incomplete: %+v", signed)
	}
}

func TestSoftwareElementRequiresUserPresence(t *testing.T) {
	element := newTestElement()
	ctx := context.Background()

	if _, err := element.ProvisionMnemonic(ctx, "primary", testMnemonic, DefaultPolicy()); err != nil {
		t.Fatalf("ProvisionMnemonic() error = %v", err)
	}
	_, err := element.SignEIP191Message(ctx, "primary", 0, "hello fluxo", Authorization{})
	if !errors.Is(err, ErrUserPresenceRequired) {
		t.Fatalf("SignEIP191Message() error = %v, want %v", err, ErrUserPresenceRequired)
	}
}

func TestSoftwareElementRejectsSecretExportPolicy(t *testing.T) {
	element := newTestElement()
	policy := DefaultPolicy()
	policy.AllowSecretExport = true

	_, err := element.ProvisionMnemonic(context.Background(), "primary", testMnemonic, policy)
	if !errors.Is(err, ErrExportNotSupported) {
		t.Fatalf("ProvisionMnemonic() error = %v, want %v", err, ErrExportNotSupported)
	}
}

func TestSoftwareElementLockPreventsUse(t *testing.T) {
	element := newTestElement()
	ctx := context.Background()

	if _, err := element.ProvisionMnemonic(ctx, "primary", testMnemonic, DefaultPolicy()); err != nil {
		t.Fatalf("ProvisionMnemonic() error = %v", err)
	}
	if err := element.Lock(ctx, "primary"); err != nil {
		t.Fatalf("Lock() error = %v", err)
	}
	_, err := element.SignEIP191Message(ctx, "primary", 0, "hello fluxo", Authorization{UserPresence: true})
	if !errors.Is(err, ErrSlotNotFound) {
		t.Fatalf("SignEIP191Message() error = %v, want %v", err, ErrSlotNotFound)
	}
}

func TestSoftwareElementPublicResponsesDoNotLeakSecrets(t *testing.T) {
	element := newTestElement()
	ctx := context.Background()

	info, err := element.ProvisionMnemonic(ctx, "primary", testMnemonic, DefaultPolicy())
	if err != nil {
		t.Fatalf("ProvisionMnemonic() error = %v", err)
	}
	signed, err := element.SignEIP191Message(ctx, "primary", 0, "hello fluxo", Authorization{UserPresence: true})
	if err != nil {
		t.Fatalf("SignEIP191Message() error = %v", err)
	}
	raw, err := json.Marshal(struct {
		Info   SlotInfo `json:"info"`
		Signed any      `json:"signed"`
	}{Info: info, Signed: signed})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	body := string(raw)
	for _, forbidden := range []string{"mnemonic", "privateKey", "test test test", "0xac0974"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("public response leaked %q: %s", forbidden, body)
		}
	}
}

func TestSoftwareElementAttestationBindsChallenge(t *testing.T) {
	element := newTestElement()
	first, err := element.Attest(context.Background(), []byte("first"))
	if err != nil {
		t.Fatalf("Attest() error = %v", err)
	}
	second, err := element.Attest(context.Background(), []byte("second"))
	if err != nil {
		t.Fatalf("Attest() error = %v", err)
	}
	if first.Fingerprint == second.Fingerprint {
		t.Fatalf("attestation fingerprint must bind challenge")
	}
	if first.DeviceID != SoftwareDeviceID || first.FirmwareVersion != SoftwareFirmwareVersion {
		t.Fatalf("attestation metadata mismatch: %+v", first)
	}
}

func newTestElement() *SoftwareElement {
	return newSoftwareElement(func() time.Time {
		return time.Unix(1700000000, 0)
	})
}
