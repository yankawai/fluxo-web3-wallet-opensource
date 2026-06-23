package vault

import (
	"errors"
	"testing"
	"time"
)

func TestSessionStoreReturnsSecretBeforeTTL(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := newSessionStore(time.Minute, func() time.Time { return now })
	sessionID, err := store.Create(testAddress, testPrivateKey)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	secret, err := store.Get(sessionID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if secret.PrivateKey != testPrivateKey || secret.Address != testAddress {
		t.Fatalf("secret mismatch: %+v", secret)
	}
}

func TestSessionStoreLockPreventsAccess(t *testing.T) {
	store := NewSessionStore(time.Minute)
	sessionID, err := store.Create(testAddress, testPrivateKey)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	store.Lock(sessionID)

	if _, err := store.Get(sessionID); !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("Get() error = %v, want %v", err, ErrSessionLocked)
	}
}

func TestSessionStoreTTLPreventsAccess(t *testing.T) {
	now := time.Unix(1700000000, 0)
	store := newSessionStore(time.Minute, func() time.Time { return now })
	sessionID, err := store.Create(testAddress, testPrivateKey)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	now = now.Add(time.Minute)

	if _, err := store.Get(sessionID); !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("Get() error = %v, want %v", err, ErrSessionLocked)
	}
}

func TestSessionStoreLockAllPreventsAccess(t *testing.T) {
	store := NewSessionStore(time.Minute)
	first, err := store.Create(testAddress, testPrivateKey)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	second, err := store.Create(testAddress, testPrivateKey)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	store.LockAll()

	for _, sessionID := range []string{first, second} {
		if _, err := store.Get(sessionID); !errors.Is(err, ErrSessionLocked) {
			t.Fatalf("Get(%s) error = %v, want %v", sessionID, err, ErrSessionLocked)
		}
	}
}
