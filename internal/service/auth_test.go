package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lifeipkg/rcp-iam-go/internal/store"
)

const adminPassword = "Admin@12345"

func newAuth(t *testing.T) (*Auth, *store.MemoryStore) {
	t.Helper()
	m := store.NewMemory()
	// 单测用低迭代，只测行为不测口令强度；生产默认 120000。
	a := New(m, time.Hour, 1000)
	err := a.Bootstrap(context.Background(), map[string]string{
		"admin": adminPassword, "operator": "Operator@12345", "viewer": "Viewer@12345",
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, m
}

func adminToken(t *testing.T, a *Auth) string {
	t.Helper()
	res, err := a.Login(context.Background(), "admin", adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	return res.Token
}

func TestWrongPasswordRejected(t *testing.T) {
	a, _ := newAuth(t)
	if _, err := a.Login(context.Background(), "admin", "not-the-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("错误口令应被拒绝，得到 %v", err)
	}
}

func TestDisabledAccountCannotLogin(t *testing.T) {
	a, _ := newAuth(t)
	token := adminToken(t, a)
	target, err := a.st.UserByUsername(context.Background(), "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdateUser(context.Background(), token, target.ID, UpdateUserInput{
		Role: "OPERATOR", Status: "DISABLED",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(context.Background(), "operator", "Operator@12345"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("停用账号应拒绝登录，得到 %v", err)
	}
}

func TestLogoutRevokesToken(t *testing.T) {
	a, _ := newAuth(t)
	token := adminToken(t, a)
	if err := a.Logout(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	res, err := a.Introspect(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if res.Active {
		t.Fatal("已吊销令牌仍被判为 active")
	}
	if _, err := a.ListUsers(context.Background(), token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("吊销后复用应 401，得到 %v", err)
	}
}

func TestViewerCannotListUsers(t *testing.T) {
	a, _ := newAuth(t)
	res, err := a.Login(context.Background(), "viewer", "Viewer@12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListUsers(context.Background(), res.Token); !errors.Is(err, ErrForbidden) {
		t.Fatalf("VIEWER 越权应被拒，得到 %v", err)
	}
}

func TestLastAdminCannotBeDemoted(t *testing.T) {
	a, _ := newAuth(t)
	token := adminToken(t, a)
	admin, err := a.st.UserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdateUser(context.Background(), token, admin.ID, UpdateUserInput{
		Role: "VIEWER", Status: "ACTIVE",
	}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("降级最后一个 ADMIN 应 409，得到 %v", err)
	}
}

func TestChangePasswordRevokesSessions(t *testing.T) {
	a, _ := newAuth(t)
	token := adminToken(t, a)
	admin, err := a.st.UserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ChangePassword(context.Background(), token, admin.ID, ChangePasswordInput{
		OldPassword: adminPassword, NewPassword: "Another@12345",
	}); err != nil {
		t.Fatal(err)
	}
	res, err := a.Introspect(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if res.Active {
		t.Fatal("改密后旧会话必须立即失效")
	}
	if _, err := a.Login(context.Background(), "admin", adminPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("旧口令仍可登录")
	}
	if _, err := a.Login(context.Background(), "admin", "Another@12345"); err != nil {
		t.Fatalf("新口令应可登录: %v", err)
	}
}

func TestPasswordHashRoundTripAndTamper(t *testing.T) {
	hash, salt, err := HashPassword("S3cret-password", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("S3cret-password", hash, salt) {
		t.Fatal("正确口令未通过")
	}
	if VerifyPassword("S3cret-passwors", hash, salt) {
		t.Fatal("篡改口令通过了校验")
	}
}

func TestPermissionsAreSingleSourced(t *testing.T) {
	if got := Permissions("ADMIN"); len(got) != 2 || !HasPermission("ADMIN", "iam:users") {
		t.Fatalf("ADMIN 权限展开错误: %v", got)
	}
	if HasPermission("VIEWER", "patrol:dispatch") {
		t.Fatal("VIEWER 不应有 patrol:dispatch")
	}
}
