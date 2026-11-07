package store

import (
	"context"
	"errors"
)

var (
	// ErrUnavailable 表示 dataway 不可用。鉴权链路对此 fail closed（503），不回落匿名。
	ErrUnavailable = errors.New("dataway unavailable")
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("conflict")
)

// User 对应 rcp-ops/migrations/V1.4.0__iam_go_store.sql 的 iam_users。
type User struct {
	ID           string
	Username     string
	DisplayName  string
	Role         string
	Status       string
	PasswordHash string
	PasswordSalt string
	CreatedAt    string
}

// Session 是 iam_sessions 与 iam_users 联查的结果。
type Session struct {
	Token     string
	UserID    string
	ExpiresAt string
	User      User
}

// Store 是本服务唯一的数据出入口。生产实现只有 DatawayStore（HTTP），
// 本仓不引入任何数据库驱动（RL-005）。
type Store interface {
	UserByUsername(ctx context.Context, username string) (User, error)
	UserByID(ctx context.Context, id string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	InsertUser(ctx context.Context, u User) error
	UpdateUser(ctx context.Context, u User) error
	InsertSession(ctx context.Context, token, userID, expiresAt string) error
	SessionByToken(ctx context.Context, token string) (Session, error)
	DeleteSession(ctx context.Context, token string) error
	DeleteSessionsByUser(ctx context.Context, userID string) error
}

// Public 去掉口令材料，接口层只能用这个视图。
func (u User) Public() User {
	u.PasswordHash = ""
	u.PasswordSalt = ""
	return u
}
