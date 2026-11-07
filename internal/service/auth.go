package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lifeipkg/rcp-iam-go/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("INVALID_CREDENTIALS")
	ErrDisabled           = errors.New("ACCOUNT_DISABLED")
	ErrUnauthorized       = errors.New("UNAUTHORIZED")
	ErrForbidden          = errors.New("FORBIDDEN")
	ErrUserNotFound       = errors.New("USER_NOT_FOUND")
	ErrUserExists         = errors.New("USERNAME_TAKEN")
	ErrLastAdmin          = errors.New("LAST_ADMIN")
	ErrWeakPassword       = errors.New("WEAK_PASSWORD")
	ErrBadUsername        = errors.New("BAD_USERNAME")
	ErrBadRole            = errors.New("BAD_ROLE")
	ErrBadStatus          = errors.New("BAD_STATUS")
	ErrOldPassword        = errors.New("OLD_PASSWORD_MISMATCH")
)

const dbTimeLayout = "2006-01-02 15:04:05"

var usernameRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)

type Auth struct {
	st   store.Store
	ttl  time.Duration
	iter int
}

func New(st store.Store, ttl time.Duration, iter int) *Auth {
	return &Auth{st: st, ttl: ttl, iter: iter}
}

type LoginResult struct {
	Token     string
	ExpiresIn int
	User      store.User
}

type Introspection struct {
	Active      bool
	UserID      string
	Username    string
	Role        string
	Permissions []string
	ExpiresAt   string
}

type CreateUserInput struct {
	Username    string
	Password    string
	DisplayName string
	Role        string
}

type UpdateUserInput struct {
	DisplayName string
	Role        string
	Status      string
}

type ChangePasswordInput struct {
	OldPassword string
	NewPassword string
}

// Permissions 是角色→权限展开的唯一位置，网关与其他服务不得复制这张表。
func Permissions(role string) []string {
	switch role {
	case "ADMIN":
		return []string{"patrol:dispatch", "iam:users"}
	case "OPERATOR":
		return []string{"patrol:dispatch"}
	default:
		return []string{}
	}
}

func HasPermission(role, permission string) bool {
	for _, p := range Permissions(role) {
		if p == permission {
			return true
		}
	}
	return false
}

// pbkdf2 是 PBKDF2-HmacSHA256 的单块（dkLen=32）实现，避免为此引入 x/crypto。
func pbkdf2(password, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := append([]byte(nil), mac.Sum(nil)...)
	out := append([]byte(nil), u...)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = append([]byte(nil), mac.Sum(nil)...)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func HashPassword(password string, iter int) (string, string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	dk := pbkdf2([]byte(password), salt, iter)
	return strconv.Itoa(iter) + ":" + base64.StdEncoding.EncodeToString(dk),
		base64.StdEncoding.EncodeToString(salt), nil
}

func VerifyPassword(password, hash, salt string) bool {
	parts := strings.SplitN(hash, ":", 2)
	if len(parts) != 2 {
		return false
	}
	iter, err := strconv.Atoi(parts[0])
	if err != nil || iter <= 0 || iter > 1000000 {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false
	}
	got := pbkdf2([]byte(password), saltBytes, iter)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randomHex(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func normalizeUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeTimestamp(s string) string {
	if s == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339, dbTimeLayout, "2006-01-02T15:04:05", "2006-01-02 15:04:05.000000"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

func publicUser(u store.User) store.User {
	u = u.Public()
	u.CreatedAt = normalizeTimestamp(u.CreatedAt)
	return u
}

func validRole(role string) bool {
	return role == "ADMIN" || role == "OPERATOR" || role == "VIEWER"
}

func validPassword(p string) bool {
	return utf8.RuneCountInString(p) >= 8 && utf8.RuneCountInString(p) <= 128
}

func (a *Auth) Login(ctx context.Context, username, password string) (LoginResult, error) {
	u, err := a.st.UserByUsername(ctx, normalizeUsername(username))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, err
	}
	if u.Status != "ACTIVE" {
		return LoginResult{}, ErrDisabled
	}
	if !VerifyPassword(password, u.PasswordHash, u.PasswordSalt) {
		return LoginResult{}, ErrInvalidCredentials
	}
	token, err := randomHex("rcp_", 32)
	if err != nil {
		return LoginResult{}, err
	}
	expires := time.Now().Add(a.ttl).UTC()
	if err := a.st.InsertSession(ctx, token, u.ID, expires.Format(dbTimeLayout)); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		Token:     token,
		ExpiresIn: int(a.ttl.Seconds()),
		User:      publicUser(u),
	}, nil
}

func (a *Auth) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return a.st.DeleteSession(ctx, token)
}

// Introspect 区分「令牌无效」(200 + active=false) 与「判不了」(错误 → 503)。
// 后者不允许回落成 active=false 之外的放行，也不允许降级到匿名。
func (a *Auth) Introspect(ctx context.Context, token string) (Introspection, error) {
	if token == "" {
		return Introspection{Active: false}, nil
	}
	s, err := a.st.SessionByToken(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Introspection{Active: false}, nil
		}
		return Introspection{}, err
	}
	return Introspection{
		Active:      true,
		UserID:      s.UserID,
		Username:    s.User.Username,
		Role:        s.User.Role,
		Permissions: Permissions(s.User.Role),
		ExpiresAt:   normalizeTimestamp(s.ExpiresAt),
	}, nil
}

func (a *Auth) CurrentUser(ctx context.Context, token string) (store.User, error) {
	s, err := a.st.SessionByToken(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.User{}, ErrUnauthorized
		}
		return store.User{}, err
	}
	return publicUser(s.User), nil
}

func (a *Auth) authorize(ctx context.Context, token, permission string) (store.User, error) {
	s, err := a.st.SessionByToken(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.User{}, ErrUnauthorized
		}
		return store.User{}, err
	}
	if permission != "" && !HasPermission(s.User.Role, permission) {
		return store.User{}, ErrForbidden
	}
	return s.User, nil
}

func (a *Auth) ListUsers(ctx context.Context, token string) ([]store.User, error) {
	if _, err := a.authorize(ctx, token, "iam:users"); err != nil {
		return nil, err
	}
	users, err := a.st.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]store.User, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	return out, nil
}

func (a *Auth) CreateUser(ctx context.Context, token string, in CreateUserInput) (store.User, error) {
	if _, err := a.authorize(ctx, token, "iam:users"); err != nil {
		return store.User{}, err
	}
	name := normalizeUsername(in.Username)
	if !usernameRe.MatchString(name) {
		return store.User{}, ErrBadUsername
	}
	if !validPassword(in.Password) {
		return store.User{}, ErrWeakPassword
	}
	if !validRole(in.Role) {
		return store.User{}, ErrBadRole
	}
	if _, err := a.st.UserByUsername(ctx, name); err == nil {
		return store.User{}, ErrUserExists
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	hash, salt, err := HashPassword(in.Password, a.iter)
	if err != nil {
		return store.User{}, err
	}
	id, err := randomHex("usr_", 8)
	if err != nil {
		return store.User{}, err
	}
	display := in.DisplayName
	if display == "" {
		display = name
	}
	u := store.User{
		ID:           id,
		Username:     name,
		DisplayName:  display,
		Role:         in.Role,
		Status:       "ACTIVE",
		PasswordHash: hash,
		PasswordSalt: salt,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := a.st.InsertUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.User{}, ErrUserExists
		}
		return store.User{}, err
	}
	return publicUser(u), nil
}

func (a *Auth) countActiveAdmins(ctx context.Context) (int, error) {
	users, err := a.st.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if u.Role == "ADMIN" && u.Status == "ACTIVE" {
			n++
		}
	}
	return n, nil
}

func (a *Auth) UpdateUser(ctx context.Context, token, userID string, in UpdateUserInput) (store.User, error) {
	if _, err := a.authorize(ctx, token, "iam:users"); err != nil {
		return store.User{}, err
	}
	if !validRole(in.Role) {
		return store.User{}, ErrBadRole
	}
	if in.Status != "ACTIVE" && in.Status != "DISABLED" {
		return store.User{}, ErrBadStatus
	}
	u, err := a.st.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.User{}, ErrUserNotFound
		}
		return store.User{}, err
	}
	wasActiveAdmin := u.Role == "ADMIN" && u.Status == "ACTIVE"
	willBeActiveAdmin := in.Role == "ADMIN" && in.Status == "ACTIVE"
	if wasActiveAdmin && !willBeActiveAdmin {
		n, err := a.countActiveAdmins(ctx)
		if err != nil {
			return store.User{}, err
		}
		if n <= 1 {
			return store.User{}, ErrLastAdmin
		}
	}
	display := in.DisplayName
	if display == "" {
		display = u.Username
	}
	u.DisplayName = display
	u.Role = in.Role
	u.Status = in.Status
	if err := a.st.UpdateUser(ctx, u); err != nil {
		return store.User{}, err
	}
	if in.Status == "DISABLED" {
		if err := a.st.DeleteSessionsByUser(ctx, u.ID); err != nil {
			return store.User{}, err
		}
	}
	return publicUser(u), nil
}

func (a *Auth) ChangePassword(ctx context.Context, token, userID string, in ChangePasswordInput) error {
	actor, err := a.authorize(ctx, token, "")
	if err != nil {
		return err
	}
	if !validPassword(in.NewPassword) {
		return ErrWeakPassword
	}
	target, err := a.st.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}
	if actor.ID == userID {
		if in.OldPassword == "" || !VerifyPassword(in.OldPassword, target.PasswordHash, target.PasswordSalt) {
			return ErrOldPassword
		}
	} else if !HasPermission(actor.Role, "iam:users") {
		return ErrForbidden
	}
	hash, salt, err := HashPassword(in.NewPassword, a.iter)
	if err != nil {
		return err
	}
	target.PasswordHash = hash
	target.PasswordSalt = salt
	if err := a.st.UpdateUser(ctx, target); err != nil {
		return err
	}
	// 改密后该用户所有会话立即失效，含本次调用所用令牌。
	return a.st.DeleteSessionsByUser(ctx, target.ID)
}

// Bootstrap 按「用户不存在才创建」写入引导账号，启动时调用一次。
func (a *Auth) Bootstrap(ctx context.Context, users map[string]string) error {
	for name, password := range users {
		key := normalizeUsername(name)
		if _, err := a.st.UserByUsername(ctx, key); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		hash, salt, err := HashPassword(password, a.iter)
		if err != nil {
			return err
		}
		id, err := randomHex("usr_", 8)
		if err != nil {
			return err
		}
		role := "VIEWER"
		if key == "admin" {
			role = "ADMIN"
		} else if key == "operator" {
			role = "OPERATOR"
		}
		if err := a.st.InsertUser(ctx, store.User{
			ID:           id,
			Username:     key,
			DisplayName:  key,
			Role:         role,
			Status:       "ACTIVE",
			PasswordHash: hash,
			PasswordSalt: salt,
			CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		}); err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return nil
}
