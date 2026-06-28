package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/perber/wiki/internal/core/auth"
)

func (s *Server) registerAdminTools() {
	s.svc.AddTools(
		server.ServerTool{
			Tool: mcp.NewTool("list_users",
				mcp.WithDescription("List all users. Requires admin role."),
			),
			Handler: s.handleListUsers,
		},
		server.ServerTool{
			Tool: mcp.NewTool("create_user",
				mcp.WithDescription("Create a new user. Requires admin role."),
				mcp.WithString("username",
					mcp.Required(),
					mcp.Description("The username"),
				),
				mcp.WithString("email",
					mcp.Required(),
					mcp.Description("The email address"),
				),
				mcp.WithString("password",
					mcp.Required(),
					mcp.Description("The password"),
				),
				mcp.WithString("role",
					mcp.Description("The role (admin, editor, viewer). Default: viewer"),
				),
			),
			Handler: s.handleCreateUser,
		},
		server.ServerTool{
			Tool: mcp.NewTool("delete_user",
				mcp.WithDescription("Delete a user by ID. Requires admin role."),
				mcp.WithString("id",
					mcp.Required(),
					mcp.Description("The user ID"),
				),
			),
			Handler: s.handleDeleteUser,
		},
	)
}

func (s *Server) handleListUsers(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleAdmin) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	users, err := s.config.UserSvc.GetUsers()
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to list users: %s", err.Error()), nil
	}

	var items []string
	for _, u := range users {
		items = append(items, "- **"+u.Username+"** ["+u.ID+"] ("+u.Role+") - "+u.Email)
	}

	if len(items) == 0 {
		return mcp.NewToolResultText("No users found."), nil
	}

	return mcp.NewToolResultText("Users:\n\n" + join(items, "\n\n")), nil
}

func (s *Server) handleCreateUser(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleAdmin) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	username := req.GetString("username", "")
	email := req.GetString("email", "")
	password := req.GetString("password", "")
	if username == "" || email == "" || password == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	role := req.GetString("role", "")
	if role == "" {
		role = auth.RoleViewer
	}
	if !auth.IsValidRole(role) {
		return mcp.NewToolResultError("Invalid role: " + role), nil
	}

	u, err := s.config.UserSvc.CreateUser(username, email, password, role)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to create user: %s", err.Error()), nil
	}

	return mcp.NewToolResultText("User created: " + u.Username + " [" + u.ID + "]"), nil
}

func (s *Server) handleDeleteUser(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleAdmin) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	id := req.GetString("id", "")
	if id == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	err := s.config.UserSvc.DeleteUser(id)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to delete user: %s", err.Error()), nil
	}

	return mcp.NewToolResultText("User deleted: " + id), nil
}
