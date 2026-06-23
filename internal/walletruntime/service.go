package walletruntime

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yankawai/fluxo-web3-wallet-opensource/internal/networks"
	"github.com/yankawai/fluxo-web3-wallet-opensource/internal/vault"
	"github.com/yankawai/fluxo-web3-wallet-opensource/internal/walletcore"
)

var ErrAddressMismatch = errors.New("private key does not match vault address")

type Service struct {
	sessions     *vault.SessionStore
	encryptVault func(mnemonic string, password string, address string) (vault.Vault, error)
	unlockVault  func(rawVault string, password string) (vault.UnlockResult, error)
}

type SessionResponse struct {
	Address       string                 `json:"address"`
	Account       walletcore.HDAccount   `json:"account"`
	Accounts      []walletcore.HDAccount `json:"accounts"`
	SessionID     string                 `json:"sessionId"`
	Networks      []networks.Network     `json:"networks"`
	ActiveChainID int64                  `json:"activeChainId"`
}

type CreateVaultResponse struct {
	Vault         vault.Vault            `json:"vault"`
	Address       string                 `json:"address"`
	Account       walletcore.HDAccount   `json:"account"`
	Accounts      []walletcore.HDAccount `json:"accounts"`
	SessionID     string                 `json:"sessionId"`
	Mnemonic      string                 `json:"mnemonic"`
	Networks      []networks.Network     `json:"networks"`
	ActiveChainID int64                  `json:"activeChainId"`
}

type UnlockVaultResponse struct {
	Address       string                 `json:"address"`
	Account       walletcore.HDAccount   `json:"account"`
	Accounts      []walletcore.HDAccount `json:"accounts"`
	SessionID     string                 `json:"sessionId"`
	Networks      []networks.Network     `json:"networks"`
	ActiveChainID int64                  `json:"activeChainId"`
	MigratedVault *vault.Vault           `json:"migratedVault,omitempty"`
}

func NewService() *Service {
	return newServiceWithVault(vault.DefaultSessionTTL, vault.EncryptMnemonic, vault.UnlockJSON)
}

func newServiceWithTTL(ttl time.Duration) *Service {
	return newServiceWithVault(ttl, vault.EncryptMnemonic, vault.UnlockJSON)
}

func newServiceWithVault(
	ttl time.Duration,
	encryptVault func(mnemonic string, password string, address string) (vault.Vault, error),
	unlockVault func(rawVault string, password string) (vault.UnlockResult, error),
) *Service {
	return &Service{
		sessions:     vault.NewSessionStore(ttl),
		encryptVault: encryptVault,
		unlockVault:  unlockVault,
	}
}

func (s *Service) CreateVault(password string) (CreateVaultResponse, error) {
	mnemonic, err := walletcore.GenerateMnemonic()
	if err != nil {
		return CreateVaultResponse{}, err
	}
	return s.createVaultFromMnemonic(password, mnemonic, true)
}

func (s *Service) ImportVault(password string, mnemonic string) (CreateVaultResponse, error) {
	if err := walletcore.ValidateMnemonic(mnemonic); err != nil {
		return CreateVaultResponse{}, err
	}
	return s.createVaultFromMnemonic(password, mnemonic, false)
}

func (s *Service) createVaultFromMnemonic(password string, mnemonic string, includeMnemonic bool) (CreateVaultResponse, error) {
	account, err := walletcore.DeriveAccount(mnemonic, 0)
	if err != nil {
		return CreateVaultResponse{}, err
	}
	encryptedVault, err := s.encryptVault(mnemonic, password, account.Address)
	if err != nil {
		return CreateVaultResponse{}, err
	}
	session, err := s.openHDSession(account, mnemonic)
	if err != nil {
		return CreateVaultResponse{}, err
	}
	accounts := []walletcore.HDAccount{account}
	responseMnemonic := ""
	if includeMnemonic {
		responseMnemonic = mnemonic
	}
	return CreateVaultResponse{
		Vault:         encryptedVault,
		Address:       session.Address,
		Account:       account,
		Accounts:      accounts,
		SessionID:     session.SessionID,
		Mnemonic:      responseMnemonic,
		Networks:      networks.DefaultNetworks(),
		ActiveChainID: networks.DefaultChainID,
	}, nil
}

func (s *Service) UnlockVault(rawVault string, password string) (UnlockVaultResponse, error) {
	result, err := s.unlockVault(rawVault, password)
	if err != nil {
		return UnlockVaultResponse{}, err
	}
	session, account, accounts, err := s.openUnlockedSession(result)
	if err != nil {
		return UnlockVaultResponse{}, err
	}
	return UnlockVaultResponse{
		Address:       session.Address,
		Account:       account,
		Accounts:      accounts,
		SessionID:     session.SessionID,
		Networks:      networks.DefaultNetworks(),
		ActiveChainID: networks.DefaultChainID,
		MigratedVault: result.MigratedVault,
	}, nil
}

func (s *Service) openUnlockedSession(result vault.UnlockResult) (SessionResponse, walletcore.HDAccount, []walletcore.HDAccount, error) {
	if result.Kind == vault.VaultKindHDMnemonic {
		account, err := walletcore.DeriveAccount(result.Mnemonic, result.ActiveAccountIndex)
		if err != nil {
			return SessionResponse{}, walletcore.HDAccount{}, nil, err
		}
		if !strings.EqualFold(account.Address, result.Address) {
			return SessionResponse{}, walletcore.HDAccount{}, nil, ErrAddressMismatch
		}
		session, err := s.openHDSession(account, result.Mnemonic)
		if err != nil {
			return SessionResponse{}, walletcore.HDAccount{}, nil, err
		}
		return session, account, []walletcore.HDAccount{account}, nil
	}

	session, err := s.openSession(result.Address, result.PrivateKey)
	if err != nil {
		return SessionResponse{}, walletcore.HDAccount{}, nil, err
	}
	account := walletcore.HDAccount{Index: 0, Path: "imported", Address: session.Address}
	return session, account, []walletcore.HDAccount{account}, nil
}

func (s *Service) openHDSession(account walletcore.HDAccount, mnemonic string) (SessionResponse, error) {
	sessionID, err := s.sessions.CreateSecret(vault.SessionSecret{
		Address:            account.Address,
		Mnemonic:           mnemonic,
		ActiveAccountIndex: account.Index,
		Kind:               vault.VaultKindHDMnemonic,
	})
	if err != nil {
		return SessionResponse{}, err
	}
	return SessionResponse{
		Address:       account.Address,
		Account:       account,
		Accounts:      []walletcore.HDAccount{account},
		SessionID:     sessionID,
		Networks:      networks.DefaultNetworks(),
		ActiveChainID: networks.DefaultChainID,
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
	privateKey := secret.PrivateKey
	if secret.Kind == vault.VaultKindHDMnemonic {
		privateKey, err = walletcore.DerivePrivateKey(secret.Mnemonic, secret.ActiveAccountIndex)
		if err != nil {
			return walletcore.SignedMessage{}, err
		}
	}
	signed, err := walletcore.SignMessage(privateKey, message)
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
