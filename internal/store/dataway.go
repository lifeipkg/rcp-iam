package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DatawayStore 是生产唯一实现：只读声明式查询 + 服务端模板化写入。
// 本文件不 import 任何数据库驱动，连接串/驱动只存在于 dataway 与部署仓。
type DatawayStore struct {
	baseURL    string
	datasource string
	client     *http.Client
}

func NewDataway(baseURL, datasource string) *DatawayStore {
	return &DatawayStore{
		baseURL:    strings.TrimRight(baseURL, "/"),
		datasource: datasource,
		client:     &http.Client{Timeout: 3 * time.Second},
	}
}

type queryRequest struct {
	Datasource string `json:"datasource"`
	SQL        string `json:"sql"`
	Params     []any  `json:"params"`
	MaxRows    int    `json:"maxRows"`
}

type queryResponse struct {
	Columns  []string         `json:"columns"`
	Rows     []map[string]any `json:"rows"`
	RowCount int              `json:"rowCount"`
}

type executeRequest struct {
	Datasource string `json:"datasource"`
	TemplateID string `json:"templateId"`
	Params     []any  `json:"params"`
}

type executeResponse struct {
	AffectedRows int `json:"affectedRows"`
}

func (d *DatawayStore) post(ctx context.Context, path string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: %s returned %d: %s", ErrUnavailable, path,
			resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%w: bad response: %v", ErrUnavailable, err)
		}
	}
	return nil
}

func (d *DatawayStore) query(ctx context.Context, sql string, params ...any) ([]map[string]any, error) {
	var out queryResponse
	err := d.post(ctx, "/dataway/query", queryRequest{
		Datasource: d.datasource,
		SQL:        sql,
		Params:     params,
		MaxRows:    100,
	}, &out)
	if err != nil {
		return nil, err
	}
	return out.Rows, nil
}

func (d *DatawayStore) execute(ctx context.Context, templateID string, params ...any) (int, error) {
	var out executeResponse
	err := d.post(ctx, "/dataway/execute", executeRequest{
		Datasource: d.datasource,
		TemplateID: templateID,
		Params:     params,
	}, &out)
	return out.AffectedRows, err
}

func cell(row map[string]any, key string) string {
	switch v := row[key].(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func userFromRow(row map[string]any) User {
	return User{
		ID:           cell(row, "user_id"),
		Username:     cell(row, "username"),
		DisplayName:  cell(row, "display_name"),
		Role:         cell(row, "role"),
		Status:       cell(row, "status"),
		PasswordHash: cell(row, "password_hash"),
		PasswordSalt: cell(row, "password_salt"),
		CreatedAt:    cell(row, "gmt_create"),
	}
}

const userColumns = "user_id, username, display_name, role, status, password_hash, password_salt, gmt_create"

func (d *DatawayStore) UserByUsername(ctx context.Context, username string) (User, error) {
	rows, err := d.query(ctx, "SELECT "+userColumns+" FROM iam_users WHERE username = ?", username)
	if err != nil {
		return User{}, err
	}
	if len(rows) == 0 {
		return User{}, ErrNotFound
	}
	return userFromRow(rows[0]), nil
}

func (d *DatawayStore) UserByID(ctx context.Context, id string) (User, error) {
	rows, err := d.query(ctx, "SELECT "+userColumns+" FROM iam_users WHERE user_id = ?", id)
	if err != nil {
		return User{}, err
	}
	if len(rows) == 0 {
		return User{}, ErrNotFound
	}
	return userFromRow(rows[0]), nil
}

func (d *DatawayStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.query(ctx,
		"SELECT user_id, username, display_name, role, status, gmt_create FROM iam_users ORDER BY username")
	if err != nil {
		return nil, err
	}
	users := make([]User, 0, len(rows))
	for _, row := range rows {
		users = append(users, userFromRow(row))
	}
	return users, nil
}

func (d *DatawayStore) InsertUser(ctx context.Context, u User) error {
	_, err := d.execute(ctx, "iam.user.insert",
		u.ID, u.Username, u.DisplayName, u.Role, u.Status, u.PasswordHash, u.PasswordSalt)
	return err
}

func (d *DatawayStore) UpdateUser(ctx context.Context, u User) error {
	_, err := d.execute(ctx, "iam.user.update",
		u.DisplayName, u.Role, u.Status, u.PasswordHash, u.PasswordSalt, u.ID)
	return err
}

// InsertSession 的 expiresAt 必须是 "2006-01-02 15:04:05"（模板里 CAST 成 TIMESTAMP）。
func (d *DatawayStore) InsertSession(ctx context.Context, token, userID, expiresAt string) error {
	_, err := d.execute(ctx, "iam.session.insert", token, userID, expiresAt)
	return err
}

// SessionByToken 把过期判定下推到数据库，避免跨库时间格式解析；
// 同时要求用户仍为 ACTIVE，停用账号的令牌立即失效。
func (d *DatawayStore) SessionByToken(ctx context.Context, token string) (Session, error) {
	rows, err := d.query(ctx,
		"SELECT s.token, s.user_id, s.expires_at, u.username, u.display_name, u.role, u.status, u.gmt_create "+
			"FROM iam_sessions s JOIN iam_users u ON u.user_id = s.user_id "+
			"WHERE s.token = ? AND s.expires_at > CURRENT_TIMESTAMP AND u.status = 'ACTIVE'",
		token)
	if err != nil {
		return Session{}, err
	}
	if len(rows) == 0 {
		return Session{}, ErrNotFound
	}
	row := rows[0]
	return Session{
		Token:     cell(row, "token"),
		UserID:    cell(row, "user_id"),
		ExpiresAt: cell(row, "expires_at"),
		User:      userFromRow(row),
	}, nil
}

func (d *DatawayStore) DeleteSession(ctx context.Context, token string) error {
	_, err := d.execute(ctx, "iam.session.delete", token)
	return err
}

func (d *DatawayStore) DeleteSessionsByUser(ctx context.Context, userID string) error {
	_, err := d.execute(ctx, "iam.session.deleteByUser", userID)
	return err
}
