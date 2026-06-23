package secureelement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yankawai/fluxo-web3-wallet-opensource/internal/walletcore"
)

const (
	SoftwareDeviceID        = "fluxo-software-se"
	SoftwareFirmwareVersion = "software-emulator-v1"
)

type SoftwareElement struct {
	mu    sync.RWMutex
	now   func() time.Time
	slots map[SlotID]softwareSlot
}

type softwareSlot struct {
	mnemonic string
	policy   Policy
	created  time.Time
	locked   bool
}

func NewSoftwareElement() *SoftwareElement {
	return newSoftwareElement(time.Now)
}

func newSoftwareElement(now func() time.Time) *SoftwareElement {
	return &SoftwareElement{
		now:   now,
		slots: make(map[SlotID]softwareSlot),
	}
}

func (e *SoftwareElement) GenerateMnemonic(ctx context.Context, slotID SlotID, policy Policy) (SlotInfo, error) {
	if err := ctx.Err(); err != nil {
		return SlotInfo{}, err
	}
	mnemonic, err := walletcore.GenerateMnemonic()
	if err != nil {
		return SlotInfo{}, err
	}
	return e.ProvisionMnemonic(ctx, slotID, mnemonic, policy)
}

func (e *SoftwareElement) ProvisionMnemonic(ctx context.Context, slotID SlotID, mnemonic string, policy Policy) (SlotInfo, error) {
	if err := ctx.Err(); err != nil {
		return SlotInfo{}, err
	}
	if err := validateSlotID(slotID); err != nil {
		return SlotInfo{}, err
	}
	if err := walletcore.ValidateMnemonic(mnemonic); err != nil {
		return SlotInfo{}, err
	}
	if policy.AllowSecretExport {
		return SlotInfo{}, ErrExportNotSupported
	}

	account, err := walletcore.DeriveAccount(mnemonic, 0)
	if err != nil {
		return SlotInfo{}, err
	}
	slot := softwareSlot{
		mnemonic: strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(mnemonic))), " "),
		policy:   policy,
		created:  e.now().UTC(),
	}

	e.mu.Lock()
	e.slots[slotID] = slot
	e.mu.Unlock()

	return slotInfo(slotID, account, slot), nil
}

func (e *SoftwareElement) DeriveAddress(ctx context.Context, slotID SlotID, accountIndex uint32) (walletcore.HDAccount, error) {
	if err := ctx.Err(); err != nil {
		return walletcore.HDAccount{}, err
	}
	slot, err := e.getSlot(slotID)
	if err != nil {
		return walletcore.HDAccount{}, err
	}
	if slot.locked {
		return walletcore.HDAccount{}, ErrSlotNotFound
	}
	return walletcore.DeriveAccount(slot.mnemonic, accountIndex)
}

func (e *SoftwareElement) SignEIP191Message(
	ctx context.Context,
	slotID SlotID,
	accountIndex uint32,
	message string,
	authorization Authorization,
) (walletcore.SignedMessage, error) {
	if err := ctx.Err(); err != nil {
		return walletcore.SignedMessage{}, err
	}
	slot, err := e.getSlot(slotID)
	if err != nil {
		return walletcore.SignedMessage{}, err
	}
	if slot.locked {
		return walletcore.SignedMessage{}, ErrSlotNotFound
	}
	if slot.policy.RequireUserPresence && !authorization.UserPresence {
		return walletcore.SignedMessage{}, ErrUserPresenceRequired
	}

	privateKey, err := walletcore.DerivePrivateKey(slot.mnemonic, accountIndex)
	if err != nil {
		return walletcore.SignedMessage{}, err
	}
	return walletcore.SignMessage(privateKey, message)
}

func (e *SoftwareElement) Attest(ctx context.Context, challenge []byte) (Attestation, error) {
	if err := ctx.Err(); err != nil {
		return Attestation{}, err
	}
	sum := sha256.Sum256(append([]byte(SoftwareDeviceID+":"+SoftwareFirmwareVersion+":"), challenge...))
	return Attestation{
		DeviceID:        SoftwareDeviceID,
		FirmwareVersion: SoftwareFirmwareVersion,
		Fingerprint:     hex.EncodeToString(sum[:8]),
		Challenge:       append([]byte(nil), challenge...),
		CreatedAt:       e.now().UTC(),
	}, nil
}

func (e *SoftwareElement) Lock(ctx context.Context, slotID SlotID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	slot, ok := e.slots[slotID]
	if !ok {
		return ErrSlotNotFound
	}
	slot.locked = true
	e.slots[slotID] = slot
	return nil
}

func (e *SoftwareElement) getSlot(slotID SlotID) (softwareSlot, error) {
	if err := validateSlotID(slotID); err != nil {
		return softwareSlot{}, err
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	slot, ok := e.slots[slotID]
	if !ok {
		return softwareSlot{}, ErrSlotNotFound
	}
	return slot, nil
}

func validateSlotID(slotID SlotID) error {
	if strings.TrimSpace(string(slotID)) == "" {
		return fmt.Errorf("%w: empty slot id", ErrInvalidCommand)
	}
	return nil
}

func slotInfo(slotID SlotID, account walletcore.HDAccount, slot softwareSlot) SlotInfo {
	return SlotInfo{
		SlotID:      slotID,
		Address:     account.Address,
		Path:        account.Path,
		Fingerprint: fingerprint(account.Address),
		CreatedAt:   slot.created,
		Policy:      slot.policy,
	}
}

func fingerprint(address string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(address)))
	return hex.EncodeToString(sum[:4])
}
