package vault

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	DefaultSessionTTL = 5 * time.Minute
	sessionIDBytes    = 32
)

var ErrSessionLocked = errors.New("wallet session is locked")

type SessionSecret struct {
	Address    string
	PrivateKey string
	ExpiresAt  time.Time
}

type SessionStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	now      func() time.Time
	sessions map[string]SessionSecret
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	return newSessionStore(ttl, time.Now)
}

func newSessionStore(ttl time.Duration, now func() time.Time) *SessionStore {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if now == nil {
		now = time.Now
	}
	return &SessionStore{
		ttl:      ttl,
		now:      now,
		sessions: make(map[string]SessionSecret),
	}
}

func (s *SessionStore) Create(address string, privateKey string) (string, error) {
	if !isEthereumAddressShape(address) {
		return "", fmt.Errorf("%w: invalid session address", ErrInvalidVault)
	}
	if strings.TrimSpace(privateKey) == "" {
		return "", fmt.Errorf("%w: missing session key", ErrInvalidVault)
	}

	sessionID, err := newSessionID()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = SessionSecret{
		Address:    address,
		PrivateKey: privateKey,
		ExpiresAt:  s.now().Add(s.ttl),
	}
	return sessionID, nil
}

func (s *SessionStore) Get(sessionID string) (SessionSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	secret, ok := s.sessions[sessionID]
	if !ok {
		return SessionSecret{}, ErrSessionLocked
	}
	if !s.now().Before(secret.ExpiresAt) {
		delete(s.sessions, sessionID)
		return SessionSecret{}, ErrSessionLocked
	}
	return secret, nil
}

func (s *SessionStore) Lock(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func (s *SessionStore) LockAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sessionID := range s.sessions {
		delete(s.sessions, sessionID)
	}
}

func newSessionID() (string, error) {
	raw, err := randomBytes(sessionIDBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
