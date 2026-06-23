package secureelement

import (
	"context"
	"errors"
	"time"

	"github.com/yankawai/fluxo-web3-wallet-opensource/internal/walletcore"
)

type Opcode uint8

const (
	OpcodePing Opcode = iota + 1
	OpcodeProvisionMnemonic
	OpcodeGenerateMnemonic
	OpcodeDeriveAddress
	OpcodeSignEIP191Message
	OpcodeAttest
	OpcodeLock
)

type Status uint16

const (
	StatusOK Status = iota
	StatusInvalidCommand
	StatusUnauthorized
	StatusNotFound
	StatusLocked
	StatusInternalError
)

var (
	ErrInvalidCommand       = errors.New("invalid secure element command")
	ErrSlotNotFound         = errors.New("secure element slot not found")
	ErrUserPresenceRequired = errors.New("secure element user presence required")
	ErrExportNotSupported   = errors.New("secure element secret export is not supported")
)

type SlotID string

type Command struct {
	Opcode    Opcode `json:"opcode"`
	SlotID    SlotID `json:"slotId,omitempty"`
	Account   uint32 `json:"account,omitempty"`
	Challenge []byte `json:"challenge,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
}

type Response struct {
	Status  Status `json:"status"`
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Transport interface {
	Exchange(ctx context.Context, command Command) (Response, error)
}

type Policy struct {
	RequireUserPresence bool `json:"requireUserPresence"`
	AllowSecretExport   bool `json:"allowSecretExport"`
}

func DefaultPolicy() Policy {
	return Policy{
		RequireUserPresence: true,
		AllowSecretExport:   false,
	}
}

type Authorization struct {
	UserPresence bool   `json:"userPresence"`
	Challenge    []byte `json:"challenge,omitempty"`
}

type SlotInfo struct {
	SlotID      SlotID    `json:"slotId"`
	Address     string    `json:"address"`
	Path        string    `json:"path"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"createdAt"`
	Policy      Policy    `json:"policy"`
}

type Attestation struct {
	DeviceID        string    `json:"deviceId"`
	FirmwareVersion string    `json:"firmwareVersion"`
	Fingerprint     string    `json:"fingerprint"`
	Challenge       []byte    `json:"challenge"`
	CreatedAt       time.Time `json:"createdAt"`
	Signature       []byte    `json:"signature,omitempty"`
}

type Device interface {
	GenerateMnemonic(ctx context.Context, slotID SlotID, policy Policy) (SlotInfo, error)
	ProvisionMnemonic(ctx context.Context, slotID SlotID, mnemonic string, policy Policy) (SlotInfo, error)
	DeriveAddress(ctx context.Context, slotID SlotID, account uint32) (walletcore.HDAccount, error)
	SignEIP191Message(ctx context.Context, slotID SlotID, account uint32, message string, authorization Authorization) (walletcore.SignedMessage, error)
	Attest(ctx context.Context, challenge []byte) (Attestation, error)
	Lock(ctx context.Context, slotID SlotID) error
}
