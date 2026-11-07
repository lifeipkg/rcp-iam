package web

import "github.com/lifeipkg/rcp-iam/internal/store"

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type introspectRequest struct {
	Token string `json:"token" binding:"required"`
}

type createUserRequest struct {
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role" binding:"required"`
}

type updateUserRequest struct {
	DisplayName string `json:"displayName"`
	Role        string `json:"role" binding:"required"`
	Status      string `json:"status" binding:"required"`
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword" binding:"required"`
}

type userView struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
}

type loginResponse struct {
	AccessToken string   `json:"accessToken"`
	TokenType   string   `json:"tokenType"`
	ExpiresIn   int      `json:"expiresIn"`
	User        userView `json:"user"`
}

type introspectResponse struct {
	Active      bool     `json:"active"`
	UserID      string   `json:"userId,omitempty"`
	Username    string   `json:"username,omitempty"`
	Role        string   `json:"role,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	ExpiresAt   string   `json:"expiresAt,omitempty"`
}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func toView(u store.User) userView {
	return userView{
		UserID:      u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        u.Role,
		Status:      u.Status,
		CreatedAt:   u.CreatedAt,
	}
}
