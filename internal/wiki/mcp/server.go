package mcp

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/server"
	"github.com/perber/wiki/internal/core/auth"
	"github.com/perber/wiki/internal/core/revision"
	"github.com/perber/wiki/internal/core/tree"
	"github.com/perber/wiki/internal/search"
)

type Config struct {
	Name        string
	Version     string
	APIKeySvc   *auth.APIKeyService
	TreeSvc     *tree.TreeService
	SlugSvc     *tree.SlugService
	SearchIndex *search.SQLiteIndex
	RevisionSvc *revision.Service
	UserSvc     *auth.UserService
}

type Server struct {
	svc    *server.MCPServer
	config Config
}

func New(config Config) *Server {
	svc := server.NewMCPServer(config.Name, config.Version)
	return &Server{svc: svc, config: config}
}

func (s *Server) Mount() http.Handler {
	s.registerReadTools()
	s.registerWriteTools()
	s.registerAdminTools()

	return server.NewStreamableHTTPServer(s.svc,
		server.WithEndpointPath("/api/mcp"),
		server.WithHTTPContextFunc(s.httpContextFunc),
	)
}

func (s *Server) httpContextFunc(ctx context.Context, r *http.Request) context.Context {
	if s.config.APIKeySvc == nil {
		return ctx
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ctx
	}

	apiKey := authHeader[7:] // "Bearer "
	user, err := s.config.APIKeySvc.Authenticate(apiKey)
	if err != nil {
		return ctx
	}

	return context.WithValue(ctx, ctxKeyUser{}, user)
}

type ctxKeyUser struct{}

func userFromContext(ctx context.Context) *auth.User {
	v := ctx.Value(ctxKeyUser{})
	if v == nil {
		return nil
	}
	if u, ok := v.(*auth.User); ok {
		return u
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return nil
}
