package store

import (
	"context"
	"strings"
	"sync"
	"time"
)

// MemoryStore 只用于单元测试。生产 main 只装配 DatawayStore；
// 不存在 "dataway 不可用就降级到内存" 的路径（鉴权 fail closed）。
type MemoryStore struct {
	mu       sync.Mutex
	users    map[string]User
	sessions map[string]Session
}

func NewMemory() *MemoryStore {
	return &MemoryStore{users: map[string]User{}, sessions: map[string]Session{}}
}

func (m *MemoryStore) UserByUsername(_ context.Context, username string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[strings.ToLower(username)]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *MemoryStore) UserByID(_ context.Context, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

func (m *MemoryStore) ListUsers(_ context.Context) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	return out, nil
}

func (m *MemoryStore) InsertUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := strings.ToLower(u.Username)
	if _, exists := m.users[key]; exists {
		return ErrConflict
	}
	if u.CreatedAt == "" {
		u.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	m.users[key] = u
	return nil
}

func (m *MemoryStore) UpdateUser(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := strings.ToLower(u.Username)
	if _, exists := m.users[key]; !exists {
		return ErrNotFound
	}
	m.users[key] = u
	return nil
}

func (m *MemoryStore) InsertSession(_ context.Context, token, userID, expiresAt string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var found User
	for _, u := range m.users {
		if u.ID == userID {
			found = u
			break
		}
	}
	m.sessions[token] = Session{Token: token, UserID: userID, ExpiresAt: expiresAt, User: found}
	return nil
}

func (m *MemoryStore) SessionByToken(_ context.Context, token string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[token]
	if !ok || s.User.Status != "ACTIVE" {
		return Session{}, ErrNotFound
	}
	exp, err := time.Parse("2006-01-02 15:04:05", s.ExpiresAt)
	if err != nil || !exp.After(time.Now().UTC()) {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (m *MemoryStore) DeleteSession(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
	return nil
}

func (m *MemoryStore) DeleteSessionsByUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for token, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, token)
		}
	}
	return nil
}
