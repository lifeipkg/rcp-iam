package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQueryRequestShapeAndRowParsing(t *testing.T) {
	var path string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"columns":["token","user_id","expires_at","username","display_name","role","status","gmt_create"],`+
			`"rows":[{"token":"rcp_abc","user_id":"usr_1","expires_at":"2026-11-07 20:00:00",`+
			`"username":"admin","display_name":"管理员","role":"ADMIN","status":"ACTIVE",`+
			`"gmt_create":"2026-11-07 12:00:00"}],"rowCount":1}`)
	}))
	defer srv.Close()

	st := NewDataway(srv.URL, "main")
	s, err := st.SessionByToken(context.Background(), "rcp_abc")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/dataway/query" {
		t.Fatalf("查询应走 /dataway/query，得到 %s", path)
	}
	if body["datasource"] != "main" {
		t.Fatalf("datasource 应为 main，得到 %v", body["datasource"])
	}
	sql, _ := body["sql"].(string)
	if !strings.Contains(sql, "FROM iam_sessions") || !strings.Contains(sql, "JOIN iam_users") {
		t.Fatalf("会话查询必须引用白名单表，得到 %s", sql)
	}
	if s.User.Username != "admin" || s.User.Role != "ADMIN" || s.Token != "rcp_abc" {
		t.Fatalf("行解析错误: %+v", s)
	}
}

func TestExecuteUsesTemplateID(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"affectedRows":1}`)
	}))
	defer srv.Close()

	st := NewDataway(srv.URL, "main")
	if err := st.InsertSession(context.Background(), "rcp_x", "usr_1", "2026-11-07 20:00:00"); err != nil {
		t.Fatal(err)
	}
	if body["templateId"] != "iam.session.insert" {
		t.Fatalf("写入必须引用服务端模板 ID，得到 %v", body["templateId"])
	}
}

func TestDatawayUnavailableIsFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	srv.Close() // 直接关闭，模拟连接不上

	st := NewDataway(srv.URL, "main")
	_, err := st.SessionByToken(context.Background(), "rcp_abc")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dataway 不可用必须返回 ErrUnavailable，得到 %v", err)
	}
}
