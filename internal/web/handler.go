package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lifeipkg/rcp-iam/internal/service"
	"github.com/lifeipkg/rcp-iam/internal/store"
)

type Handler struct {
	auth *service.Auth
}

// NewRouter 的路由一律写完整字面量路径：rcp-contracts/tools/contract_check.py
// 会机械抽取 r.GET/r.POST/... 与 OpenAPI 做两向差集，变量拼接会让对表失效。
func NewRouter(a *service.Auth) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	h := &Handler{auth: a}

	// 运维探活不属于公开契约路由，用 Handle 注册，避免被契约对表误算成业务接口。
	r.Handle(http.MethodGet, "/actuator/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP"})
	})

	r.POST("/api/v1/iam/login", h.login)
	r.POST("/api/v1/iam/logout", h.logout)
	r.POST("/api/v1/iam/introspect", h.introspect)
	r.GET("/api/v1/iam/me", h.me)
	r.GET("/api/v1/iam/users", h.listUsers)
	r.POST("/api/v1/iam/users", h.createUser)
	r.PUT("/api/v1/iam/users/:userId", h.updateUser)
	r.PUT("/api/v1/iam/users/:userId/password", h.changePassword)
	return r
}

func bearerToken(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

func badRequest(c *gin.Context) {
	c.JSON(http.StatusBadRequest, errorBody{Error: "BAD_REQUEST", Message: "请求体校验失败"})
}

// fail 把领域错误映射到契约状态码。dataway 不可用一律 503，
// 不回落匿名、不降级放行（鉴权 fail closed）。
func fail(c *gin.Context, err error) {
	if errors.Is(err, store.ErrUnavailable) {
		c.JSON(http.StatusServiceUnavailable,
			errorBody{Error: "IAM_UNAVAILABLE", Message: "鉴权依赖不可用，拒绝请求"})
		return
	}
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, service.ErrInvalidCredentials),
		errors.Is(err, service.ErrDisabled),
		errors.Is(err, service.ErrUnauthorized),
		errors.Is(err, service.ErrOldPassword):
		code = http.StatusUnauthorized
	case errors.Is(err, service.ErrForbidden):
		code = http.StatusForbidden
	case errors.Is(err, service.ErrUserNotFound):
		code = http.StatusNotFound
	case errors.Is(err, service.ErrUserExists), errors.Is(err, service.ErrLastAdmin):
		code = http.StatusConflict
	case errors.Is(err, service.ErrWeakPassword),
		errors.Is(err, service.ErrBadUsername),
		errors.Is(err, service.ErrBadRole),
		errors.Is(err, service.ErrBadStatus):
		code = http.StatusBadRequest
	}
	c.JSON(code, errorBody{Error: err.Error()})
}

func (h *Handler) login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c)
		return
	}
	res, err := h.auth.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, loginResponse{
		AccessToken: res.Token,
		TokenType:   "Bearer",
		ExpiresIn:   res.ExpiresIn,
		User:        toView(res.User),
	})
}

func (h *Handler) logout(c *gin.Context) {
	if err := h.auth.Logout(c.Request.Context(), bearerToken(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) introspect(c *gin.Context) {
	var req introspectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c)
		return
	}
	res, err := h.auth.Introspect(c.Request.Context(), req.Token)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, introspectResponse{
		Active:      res.Active,
		UserID:      res.UserID,
		Username:    res.Username,
		Role:        res.Role,
		Permissions: res.Permissions,
		ExpiresAt:   res.ExpiresAt,
	})
}

func (h *Handler) me(c *gin.Context) {
	u, err := h.auth.CurrentUser(c.Request.Context(), bearerToken(c))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, toView(u))
}

func (h *Handler) listUsers(c *gin.Context) {
	users, err := h.auth.ListUsers(c.Request.Context(), bearerToken(c))
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]userView, 0, len(users))
	for _, u := range users {
		out = append(out, toView(u))
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handler) createUser(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c)
		return
	}
	u, err := h.auth.CreateUser(c.Request.Context(), bearerToken(c), service.CreateUserInput{
		Username:    req.Username,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		Role:        req.Role,
	})
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, toView(u))
}

func (h *Handler) updateUser(c *gin.Context) {
	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c)
		return
	}
	u, err := h.auth.UpdateUser(c.Request.Context(), bearerToken(c), c.Param("userId"), service.UpdateUserInput{
		DisplayName: req.DisplayName,
		Role:        req.Role,
		Status:      req.Status,
	})
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, toView(u))
}

func (h *Handler) changePassword(c *gin.Context) {
	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c)
		return
	}
	err := h.auth.ChangePassword(c.Request.Context(), bearerToken(c), c.Param("userId"),
		service.ChangePasswordInput{OldPassword: req.OldPassword, NewPassword: req.NewPassword})
	if err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
