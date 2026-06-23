package walletruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yankawai/go-web3-wallet/internal/vault"
	"github.com/yankawai/go-web3-wallet/internal/walletcore"
)

var ErrAddressMismatch = errors.New("private key does not match vault address")

type Service struct {
	sessions     *vault.SessionStore
	encryptVault func(privateKey string, password string, address string) (vault.Vault, error)
	decryptVault func(vault.Vault, string) (vault.UnlockResult, error)
}

type SessionResponse struct {
	Address   string `json:"address"`
	SessionID string `json:"sessionId"`
}

type CreateVaultResponse struct {
	Vault     vault.Vault `json:"vault"`
	Address   string      `json:"address"`
	SessionID string      `json:"sessionId"`
}

type UnlockVaultResponse struct {
	Address       string       `json:"address"`
	SessionID     string       `json:"sessionId"`
	MigratedVault *vault.Vault `json:"migratedVault,omitempty"`
}

func NewService() *Service {
	return newServiceWithVault(vault.DefaultSessionTTL, vault.Encrypt, vault.Decrypt)
}

func newServiceWithTTL(ttl time.Duration) *Service {
	return newServiceWithVault(ttl, vault.Encrypt, vault.Decrypt)
}

func newServiceWithVault(
	ttl time.Duration,
	encryptVault func(privateKey string, password string, address string) (vault.Vault, error),
	decryptVault func(vault.Vault, string) (vault.UnlockResult, error),
) *Service {
	return &Service{
		sessions:     vault.NewSessionStore(ttl),
		encryptVault: encryptVault,
		decryptVault: decryptVault,
	}
}

func (s *Service) CreateVault(password string) (CreateVaultResponse, error) {
	wallet, err := walletcore.GenerateWallet()
	if err != nil {
		return CreateVaultResponse{}, err
	}
	encryptedVault, err := s.encryptVault(wallet.PrivateKey, password, wallet.Address)
	if err != nil {
		return CreateVaultResponse{}, err
	}
	session, err := s.openSession(wallet.Address, wallet.PrivateKey)
	if err != nil {
		return CreateVaultResponse{}, err
	}
	return CreateVaultResponse{
		Vault:     encryptedVault,
		Address:   session.Address,
		SessionID: session.SessionID,
	}, nil
}

func (s *Service) UnlockVault(rawVault string, password string) (UnlockVaultResponse, error) {
	var encryptedVault vault.Vault
	if err := json.Unmarshal([]byte(rawVault), &encryptedVault); err != nil {
		return UnlockVaultResponse{}, fmt.Errorf("%w: invalid vault json", vault.ErrInvalidVault)
	}
	result, err := s.decryptVault(encryptedVault, password)
	if err != nil {
		return UnlockVaultResponse{}, err
	}
	session, err := s.openSession(result.Address, result.PrivateKey)
	if err != nil {
		return UnlockVaultResponse{}, err
	}
	return UnlockVaultResponse{
		Address:       session.Address,
		SessionID:     session.SessionID,
		MigratedVault: result.MigratedVault,
	}, nil
}

func (s *Service) openSession(address string, privateKey string) (SessionResponse, error) {
	derivedAddress, err := walletcore.AddressFromPrivateKey(privateKey)
	if err != nil {
		return SessionResponse{}, err
	}
	if !strings.EqualFold(derivedAddress, address) {
		return SessionResponse{}, ErrAddressMismatch
	}

	sessionID, err := s.sessions.Create(derivedAddress, privateKey)
	if err != nil {
		return SessionResponse{}, err
	}
	return SessionResponse{
		Address:   derivedAddress,
		SessionID: sessionID,
	}, nil
}

func (s *Service) SignMessage(sessionID string, message string) (walletcore.SignedMessage, error) {
	secret, err := s.sessions.Get(sessionID)
	if err != nil {
		return walletcore.SignedMessage{}, err
	}
	signed, err := walletcore.SignMessage(secret.PrivateKey, message)
	if err != nil {
		return walletcore.SignedMessage{}, err
	}
	if !strings.EqualFold(signed.Address, secret.Address) {
		return walletcore.SignedMessage{}, fmt.Errorf("%w: signed as %s", ErrAddressMismatch, signed.Address)
	}
	return signed, nil
}

func (s *Service) Lock(sessionID string) {
	s.sessions.Lock(sessionID)
}

func (s *Service) LockAll() {
	s.sessions.LockAll()
}
