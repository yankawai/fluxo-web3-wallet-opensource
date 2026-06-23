package walletruntime

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yankawai/go-web3-wallet/internal/vault"
	"github.com/yankawai/go-web3-wallet/internal/walletcore"
)

var ErrAddressMismatch = errors.New("private key does not match vault address")

type Service struct {
	sessions *vault.SessionStore
}

type SessionResponse struct {
	Address   string `json:"address"`
	SessionID string `json:"sessionId"`
}

func NewService() *Service {
	return &Service{
		sessions: vault.NewSessionStore(vault.DefaultSessionTTL),
	}
}

func newServiceWithTTL(ttl time.Duration) *Service {
	return &Service{
		sessions: vault.NewSessionStore(ttl),
	}
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
