package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

type sidKeyState struct {
	mu sync.Mutex

	sid      string
	obtained time.Time
	validFor time.Duration

	failCount   int
	lastFailure time.Time
}

type sidManager struct {
	mu     sync.Mutex
	states map[string]*sidKeyState
}

func newSIDManager() *sidManager {
	return &sidManager{states: make(map[string]*sidKeyState)}
}

var sharedSIDManager = newSIDManager()

func (m *sidManager) stateFor(key string) *sidKeyState {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, ok := m.states[key]
	if !ok {
		st = &sidKeyState{}
		m.states[key] = st
	}
	return st
}

func (m *sidManager) GetOrAuthenticate(ctx context.Context, key string, validFor time.Duration, log logr.Logger, authFn func(context.Context) (string, error)) (string, error) {
	st := m.stateFor(key)
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	if st.sid != "" && now.Sub(st.obtained) < st.validFor {
		return st.sid, nil
	}

	if st.failCount > 0 {
		backoff := authBackoff(st.failCount)
		if now.Sub(st.lastFailure) < backoff {
			return "", fmt.Errorf("auth throttled for %s (retry in %s)", key, backoff-now.Sub(st.lastFailure))
		}
	}

	sid, err := authFn(ctx)
	if err != nil {
		st.failCount++
		st.lastFailure = now
		return "", err
	}

	st.sid = sid
	st.obtained = now
	st.validFor = validFor
	st.failCount = 0
	st.lastFailure = time.Time{}
	log.Info("Authenticated and cached Pi-hole session", "cacheKey", key, "validFor", validFor.String())
	return st.sid, nil
}

func authBackoff(failures int) time.Duration {
	// 1s, 2s, 4s, ... up to 30s
	backoff := time.Second << (failures - 1)
	if backoff > 30*time.Second {
		return 30 * time.Second
	}
	return backoff
}
