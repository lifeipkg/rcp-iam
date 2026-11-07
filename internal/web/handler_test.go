package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lifeipkg/rcp-iam/internal/service"
	"github.com/lifeipkg/rcp-iam/internal/store"
)

func newTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	m := store.NewMemory()
	a := service.New(m, time.Hour, 1000)
	if err := a.Bootstrap(context.Background(), map[string]string{
		"admin": "Admin@12345", "operator": "Operator@12345", "viewer": "Viewer@12345",
	}); err != nil {
		t.Fatal(err)
	}
	return NewRouter(a)
}

func do(r http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func login(t *testing.T, r http.Handler, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(loginRequest{Username: username, Password: password})
	w := do(r, http.MethodPost, "/api/v1/iam/login", string(body), "")
	if w.Code != http.StatusOK {
		t.Fatalf("登录失败: %d %s", w.Code, w.Body.String())
	}
	var res loginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res.AccessToken
}

func TestLoginAndMe(t *testing.T) {
	r := newTestRouter(t)
	token := login(t, r, "admin", "Admin@12345")
	if token == "" {
		t.Fatal("未签发令牌")
	}
	w := do(r, http.MethodGet, "/api/v1/iam/me", "", token)
	if w.Code != http.StatusOK {
		t.Fatalf("/me 应 200，得到 %d %s", w.Code, w.Body.String())
	}
}

func TestUsersRequireAdmin(t *testing.T) {
	r := newTestRouter(t)
	if w := do(r, http.MethodGet, "/api/v1/iam/users", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，得到 %d", w.Code)
	}
	viewer := login(t, r, "viewer", "Viewer@12345")
	if w := do(r, http.MethodGet, "/api/v1/iam/users", "", viewer); w.Code != http.StatusForbidden {
		t.Fatalf("VIEWER 应 403，得到 %d", w.Code)
	}
	admin := login(t, r, "admin", "Admin@12345")
	if w := do(r, http.MethodGet, "/api/v1/iam/users", "", admin); w.Code != http.StatusOK {
		t.Fatalf("ADMIN 应 200，得到 %d", w.Code)
	}
}

func TestIntrospectInactiveToken(t *testing.T) {
	r := newTestRouter(t)
	w := do(r, http.MethodPost, "/api/v1/iam/introspect", `{"token":"rcp_not-issued"}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("内省无效令牌应 200，得到 %d", w.Code)
	}
	var res introspectResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Active {
		t.Fatal("未签发令牌被判为 active")
	}
}

func TestHealthEndpoint(t *testing.T) {
	r := newTestRouter(t)
	if w := do(r, http.MethodGet, "/actuator/health", "", ""); w.Code != http.StatusOK {
		t.Fatalf("探活应 200，得到 %d", w.Code)
	}
}
