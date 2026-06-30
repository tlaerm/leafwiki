package auth

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	coreauth "github.com/perber/wiki/internal/core/auth"
	httpinternal "github.com/perber/wiki/internal/http"
	authmw "github.com/perber/wiki/internal/http/middleware/auth"
	"github.com/perber/wiki/internal/http/middleware/security"
	"github.com/perber/wiki/internal/http/middleware/utils"
)

// DisableRefreshTokenRateLimit can be set via ldflags for E2E/debug builds.
var DisableRefreshTokenRateLimit = "false"

// Routes is the RouteRegistrar for the auth domain.
type Routes struct {
	login             *LoginUseCase
	logout            *LogoutUseCase
	refreshToken      *RefreshTokenUseCase
	createUser        *CreateUserUseCase
	updateUser        *UpdateUserUseCase
	changeOwnPassword *ChangeOwnPasswordUseCase
	deleteUser        *DeleteUserUseCase
	getUsers          *GetUsersUseCase
	getUserByID       *GetUserByIDUseCase
	authService       *coreauth.AuthService
	apiKeyService     *coreauth.APIKeyService
}

// RoutesConfig holds the dependencies to build an auth Routes instance.
type RoutesConfig struct {
	Login             *LoginUseCase
	Logout            *LogoutUseCase
	RefreshToken      *RefreshTokenUseCase
	CreateUser        *CreateUserUseCase
	UpdateUser        *UpdateUserUseCase
	ChangeOwnPassword *ChangeOwnPasswordUseCase
	DeleteUser        *DeleteUserUseCase
	GetUsers          *GetUsersUseCase
	GetUserByID       *GetUserByIDUseCase
	AuthService       *coreauth.AuthService
	APIKeyService     *coreauth.APIKeyService
}

// NewRoutes constructs the auth RouteRegistrar.
func NewRoutes(cfg RoutesConfig) *Routes {
	return &Routes{
		login:             cfg.Login,
		logout:            cfg.Logout,
		refreshToken:      cfg.RefreshToken,
		createUser:        cfg.CreateUser,
		updateUser:        cfg.UpdateUser,
		changeOwnPassword: cfg.ChangeOwnPassword,
		deleteUser:        cfg.DeleteUser,
		getUsers:          cfg.GetUsers,
		getUserByID:       cfg.GetUserByID,
		authService:       cfg.AuthService,
		apiKeyService:     cfg.APIKeyService,
	}
}

// RegisterRoutes implements RouteRegistrar.
func (r *Routes) RegisterRoutes(ctx httpinternal.RouterContext) {
	opts := ctx.Opts

	loginRateLimiter := security.NewRateLimiter(10, 5*time.Minute, true)

	nonAuth := ctx.Base.Group("/api")
	nonAuth.POST("/auth/login", loginRateLimiter, r.handleLogin(ctx))
	if DisableRefreshTokenRateLimit == "true" {
		nonAuth.POST("/auth/refresh-token", r.handleRefreshToken(ctx))
	} else {
		refreshRateLimiter := security.NewRateLimiter(30, time.Minute, false)
		nonAuth.POST("/auth/refresh-token", refreshRateLimiter, r.handleRefreshToken(ctx))
	}

	// Config endpoint also lives here as it issues the CSRF cookie.
	nonAuth.GET("/config", r.handleConfig(ctx))

	// /auth/me uses optional auth so that unauthenticated callers get 200+null
	// instead of 401, which would cause browsers behind a Basic Auth reverse
	// proxy to discard their cached credentials.
	meGroup := ctx.Base.Group("/api")
	meGroup.Use(
		authmw.InjectPublicEditor(opts.AuthDisabled),
		authmw.OptionalAuth(r.authService, ctx.AuthCookies),
	)
	meGroup.GET("/auth/me", r.handleMe)

	authGroup := ctx.Base.Group("/api")
	authGroup.Use(
		authmw.InjectPublicEditor(opts.AuthDisabled),
		authmw.RequireAuth(r.authService, ctx.AuthCookies, opts.AuthDisabled),
		security.CSRFMiddleware(ctx.CSRFCookie),
	)

	authGroup.POST("/auth/logout", r.handleLogout(ctx))

	authGroup.POST("/users", authmw.RequireAdmin(opts.AuthDisabled), r.handleCreateUser)
	authGroup.GET("/users", authmw.RequireAdmin(opts.AuthDisabled), r.handleGetUsers)
	authGroup.PUT("/users/:id", authmw.RequireSelfOrAdmin(opts.AuthDisabled), r.handleUpdateUser)
	authGroup.DELETE("/users/:id", authmw.RequireAdmin(opts.AuthDisabled), r.handleDeleteUser)

	if !opts.AuthDisabled {
		authGroup.PUT("/users/me/password", r.handleChangeOwnPassword)
	}

	// API key routes (require editor or admin)
	authGroup.POST("/apikeys", authmw.RequireEditorOrAdmin(opts.AuthDisabled), r.handleCreateAPIKey)
	authGroup.GET("/apikeys", authmw.RequireEditorOrAdmin(opts.AuthDisabled), r.handleListAPIKeys)
	authGroup.DELETE("/apikeys/:id", authmw.RequireEditorOrAdmin(opts.AuthDisabled), r.handleRevokeAPIKey)
}

// ─── Handlers ───────────────────────────────────────────────────────────────

func writeAuthCookieError(c *gin.Context, err error, httpsMsg, internalMsg, logMsg string) {
	if errors.Is(err, utils.ErrHTTPSRequired) {
		respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthCookieFailed, httpsMsg, "https required for auth cookies use allow insecure")
		return
	}
	slog.Default().Error(logMsg, "error", err)
	respondWithAuthStatusError(c, http.StatusInternalServerError, ErrCodeAuthInternalError, internalMsg, "failed to issue auth cookie")
}

func (r *Routes) handleConfig(ctx httpinternal.RouterContext) gin.HandlerFunc {
	opts := ctx.Opts
	return func(c *gin.Context) {
		if _, err := ctx.CSRFCookie.Issue(c); err != nil {
			writeAuthCookieError(c, err,
				"HTTPS is required for auth cookies. Use HTTPS or start LeafWiki with --allow-insecure for trusted plain HTTP setups.",
				"Failed to issue CSRF cookie",
				"failed to issue config CSRF cookie",
			)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"publicAccess":            opts.PublicAccess,
			"hideLinkMetadataSection": opts.HideLinkMetadataSection,
			"authDisabled":            opts.AuthDisabled,
			"basePath":                opts.BasePath,
			"maxAssetUploadSizeBytes": opts.MaxAssetUploadSizeBytes,
			"enableRevision":          opts.EnableRevision,
			"enableLinkRefactor":      opts.EnableLinkRefactor,
			"httpRemoteUserEnabled":   opts.HTTPRemoteUser.Enabled,
			"httpRemoteUserLogoutUrl": opts.HTTPRemoteUser.LogoutURL,
		})
	}
}

// handleMe returns the currently authenticated user or null.
// Uses TryGetUser (not MustGetUser) so unauthenticated callers receive 200+null
// instead of 401, avoiding the Basic Auth credential-reset issue (RFC 9110 §15.5.2).
// Cache headers prevent reverse proxies from caching the identity response.
func (r *Routes) handleMe(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", time.Unix(0, 0).UTC().Format(http.TimeFormat))

	user := authmw.TryGetUser(c)
	if user == nil {
		c.JSON(http.StatusOK, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
	})
}

func (r *Routes) handleLogin(rctx httpinternal.RouterContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Identifier string `json:"identifier" binding:"required"`
			Password   string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthInvalidPayload, "Invalid login payload", "invalid login payload")
			return
		}
		out, err := r.login.Execute(c.Request.Context(), LoginInput{
			Identifier: req.Identifier, Password: req.Password,
		})
		if err != nil {
			respondWithAuthError(c, err)
			return
		}
		if _, err := rctx.CSRFCookie.Issue(c); err != nil {
			writeAuthCookieError(c, err,
				"HTTPS is required for login cookies. Use HTTPS or start LeafWiki with --allow-insecure for trusted plain HTTP setups.",
				"Failed to issue CSRF cookie",
				"failed to issue login CSRF cookie",
			)
			return
		}
		if err := rctx.AuthCookies.Set(c, out.Token.Token, out.Token.RefreshToken); err != nil {
			if errors.Is(err, utils.ErrHTTPSRequired) {
				respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthCookieFailed,
					"HTTPS is required for auth cookies. Use HTTPS or start LeafWiki with --allow-insecure for trusted plain HTTP setups.",
					"https required for auth cookies use allow insecure")
				return
			}
			respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthCookieFailed, "Failed to set authentication cookies", "failed to set authentication cookies")
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message":              "Login successful",
			"user":                 out.Token.User,
			"accessTokenExpiresAt": out.Token.AccessTokenExpiresAt,
		})
	}
}

func (r *Routes) handleLogout(rctx httpinternal.RouterContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		refreshToken, _ := rctx.AuthCookies.ReadRefresh(c)
		if refreshToken != "" {
			if err := r.logout.Execute(c.Request.Context(), LogoutInput{RefreshToken: refreshToken}); err != nil {
				log.Printf("[INFO] Unable to revoke the refresh token: %v", err)
			}
		}
		if err := rctx.AuthCookies.Clear(c); err != nil {
			log.Printf("[INFO] Unable to clear auth cookies: %v", err)
			respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthCookieFailed, "Failed to clear authentication cookies", "failed to clear authentication cookies")
			return
		}
		if err := rctx.CSRFCookie.Clear(c); err != nil {
			log.Printf("[INFO] Unable to clear CSRF cookie: %v", err)
			respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthCsrfFailed, "Failed to clear CSRF cookie", "failed to clear csrf cookie")
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
	}
}

func (r *Routes) handleRefreshToken(rctx httpinternal.RouterContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		rt, err := rctx.AuthCookies.ReadRefresh(c)
		if err != nil || rt == "" {
			respondWithAuthStatusError(c, http.StatusUnprocessableEntity, ErrCodeAuthInvalidRefreshToken, "Missing or invalid refresh token", "missing or invalid refresh token")
			return
		}
		out, err := r.refreshToken.Execute(c.Request.Context(), RefreshTokenInput{RefreshToken: rt})
		if err != nil {
			respondWithAuthError(c, err)
			return
		}
		if _, err := rctx.CSRFCookie.Issue(c); err != nil {
			writeAuthCookieError(c, err,
				"HTTPS is required for auth cookies. Use HTTPS or start LeafWiki with --allow-insecure for trusted plain HTTP setups.",
				"Failed to issue CSRF cookie",
				"failed to issue refresh CSRF cookie",
			)
			return
		}
		if err := rctx.AuthCookies.Set(c, out.Token.Token, out.Token.RefreshToken); err != nil {
			if errors.Is(err, utils.ErrHTTPSRequired) {
				respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthCookieFailed,
					"HTTPS is required for auth cookies. Use HTTPS or start LeafWiki with --allow-insecure for trusted plain HTTP setups.",
					"https required for auth cookies use allow insecure")
				return
			}
			respondWithAuthStatusError(c, http.StatusInternalServerError, ErrCodeAuthCookieFailed, "Failed to set authentication cookies", "failed to set authentication cookies")
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message":              "Token refreshed",
			"user":                 out.Token.User,
			"accessTokenExpiresAt": out.Token.AccessTokenExpiresAt,
		})
	}
}

func (r *Routes) handleCreateUser(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
		Role     string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthInvalidRequest, "Invalid request", "invalid request")
		return
	}
	out, err := r.createUser.Execute(c.Request.Context(), CreateUserInput{
		Username: req.Username, Email: req.Email, Password: req.Password, Role: req.Role,
	})
	if err != nil {
		respondWithAuthError(c, err)
		return
	}
	c.JSON(http.StatusCreated, out.User)
}

func (r *Routes) handleGetUsers(c *gin.Context) {
	out, err := r.getUsers.Execute(c.Request.Context())
	if err != nil {
		respondWithAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, out.Users)
}

func (r *Routes) handleUpdateUser(c *gin.Context) {
	id := c.Param("id")
	requester := authmw.MustGetUser(c)
	if requester == nil {
		return
	}
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthInvalidRequest, "Invalid request", "invalid request")
		return
	}
	out, err := r.updateUser.Execute(c.Request.Context(), UpdateUserInput{
		ID: id, Username: req.Username, Email: req.Email, Password: req.Password, Role: req.Role,
		RequesterIsAdmin: requester.HasRole(coreauth.RoleAdmin),
	})
	if err != nil {
		respondWithAuthError(c, err)
		return
	}
	c.JSON(http.StatusOK, out.User)
}

func (r *Routes) handleDeleteUser(c *gin.Context) {
	id := c.Param("id")
	if err := r.deleteUser.Execute(c.Request.Context(), DeleteUserInput{ID: id}); err != nil {
		respondWithAuthError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (r *Routes) handleChangeOwnPassword(c *gin.Context) {
	user := authmw.MustGetUser(c)
	if user == nil {
		return
	}
	var req struct {
		OldPassword string `json:"oldPassword" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthInvalidRequest, "Invalid request", "invalid request")
		return
	}
	if err := r.changeOwnPassword.Execute(c.Request.Context(), ChangeOwnPasswordInput{
		UserID: user.ID, OldPassword: req.OldPassword, NewPassword: req.NewPassword,
	}); err != nil {
		respondWithAuthError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (r *Routes) handleCreateAPIKey(c *gin.Context) {
	user := authmw.MustGetUser(c)
	if user == nil {
		return
	}
	var req struct {
		Name       string  `json:"name" binding:"required,max=100"`
		ExpiresIn  *string `json:"expiresIn"` // optional, e.g. "30d", "90d"
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthInvalidRequest, "Invalid request", "invalid request")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn != "" {
		d, err := parseDuration(*req.ExpiresIn)
		if err != nil {
			respondWithAuthStatusError(c, http.StatusBadRequest, ErrCodeAuthInvalidRequest, "Invalid duration format (e.g. 30d, 90d)", "invalid duration")
			return
		}
		expiresAt = timePtr(time.Now().Add(d))
	}

	out, err := r.apiKeyService.Create(user.ID, req.Name, expiresAt)
	if err != nil {
		slog.Default().Error("failed to create api key", "error", err, "userID", user.ID)
		respondWithAuthStatusError(c, http.StatusInternalServerError, ErrCodeAuthInternalError, "Failed to create API key", "failed to create api key")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":        out.ID,
		"name":      out.Name,
		"key":       out.Key,
		"expiresAt": out.ExpiresAt,
		"createdAt": out.CreatedAt,
	})
}

func (r *Routes) handleListAPIKeys(c *gin.Context) {
	user := authmw.MustGetUser(c)
	if user == nil {
		return
	}
	keys, err := r.apiKeyService.List(user.ID)
	if err != nil {
		slog.Default().Error("failed to list api keys", "error", err, "userID", user.ID)
		respondWithAuthStatusError(c, http.StatusInternalServerError, ErrCodeAuthInternalError, "Failed to list API keys", "failed to list api keys")
		return
	}

	result := make([]gin.H, 0, len(keys))
	for _, k := range keys {
		result = append(result, gin.H{
			"id":         k.ID,
			"name":       k.Name,
			"expiresAt":  k.ExpiresAt,
			"createdAt":  k.CreatedAt,
			"lastUsedAt": k.LastUsedAt,
		})
	}
	c.JSON(http.StatusOK, result)
}

func (r *Routes) handleRevokeAPIKey(c *gin.Context) {
	id := c.Param("id")
	user := authmw.MustGetUser(c)
	if user == nil {
		return
	}
	if err := r.apiKeyService.Revoke(id, user.ID); err != nil {
		if errors.Is(err, coreauth.ErrAPIKeyNotFound) {
			respondWithAuthStatusError(c, http.StatusNotFound, ErrCodeAuthUserNotFound, "API key not found", "api key not found")
			return
		}
		slog.Default().Error("failed to revoke api key", "error", err, "keyID", id)
		respondWithAuthStatusError(c, http.StatusInternalServerError, ErrCodeAuthInternalError, "Failed to revoke API key", "failed to revoke api key")
		return
	}
	c.Status(http.StatusNoContent)
}

func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	unit := s[len(s)-1:]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	switch unit {
	case "s":
		return time.Duration(n) * time.Second, nil
	case "d":
		return time.Duration(n) * 24 * time.Hour, nil
	case "h":
		return time.Duration(n) * time.Hour, nil
	case "w":
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	case "m":
		return time.Duration(n) * 30 * 24 * time.Hour, nil
	case "y":
		return time.Duration(n) * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported duration unit: %s", s)
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
