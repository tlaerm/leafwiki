package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/perber/wiki/internal/core/auth"
	"github.com/perber/wiki/internal/core/tree"
)

func (s *Server) registerWriteTools() {
	s.svc.AddTools(
		server.ServerTool{
			Tool: mcp.NewTool("create_page",
				mcp.WithDescription("Create a new page. Requires editor or admin role."),
				mcp.WithString("title",
					mcp.Required(),
					mcp.Description("The title of the page"),
				),
				mcp.WithString("content",
					mcp.Required(),
					mcp.Description("The markdown content of the page"),
				),
				mcp.WithString("parentID",
					mcp.Description("The ID of the parent section (optional, creates at root if omitted)"),
				),
			),
			Handler: s.handleCreatePage,
		},
		server.ServerTool{
			Tool: mcp.NewTool("update_page",
				mcp.WithDescription("Update an existing page. Requires editor or admin role."),
				mcp.WithString("id",
					mcp.Required(),
					mcp.Description("The ID of the page"),
				),
				mcp.WithString("title",
					mcp.Description("New title (optional)"),
				),
				mcp.WithString("content",
					mcp.Description("New content (optional)"),
				),
			),
			Handler: s.handleUpdatePage,
		},
		server.ServerTool{
			Tool: mcp.NewTool("delete_page",
				mcp.WithDescription("Delete a page. Requires editor or admin role."),
				mcp.WithString("id",
					mcp.Required(),
					mcp.Description("The ID of the page"),
				),
				mcp.WithBoolean("recursive",
					mcp.Description("Delete children recursively (default false)"),
				),
			),
			Handler: s.handleDeletePage,
		},
		server.ServerTool{
			Tool: mcp.NewTool("move_page",
				mcp.WithDescription("Move a page to a different parent section. Requires editor or admin role."),
				mcp.WithString("id",
					mcp.Required(),
					mcp.Description("The ID of the page to move"),
				),
				mcp.WithString("parentID",
					mcp.Required(),
					mcp.Description("The ID of the new parent section"),
				),
			),
			Handler: s.handleMovePage,
		},
	)
}

func (s *Server) handleCreatePage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleEditor) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	title := req.GetString("title", "")
	content := req.GetString("content", "")
	if title == "" || content == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	parentID := req.GetString("parentID", "")
	slug := slugFromTitle(title)
	kind := tree.NodeKindPage

	var pID *string
	if parentID != "" {
		pID = &parentID
	}

	id, err := s.config.TreeSvc.CreateNode(user.ID, pID, title, slug, &kind)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to create page: %s", err.Error()), nil
	}

	err = s.config.TreeSvc.UpdateNode(user.ID, *id, title, slug, &content, tree.VersionUnchecked, false)
	if err != nil {
		s.config.TreeSvc.DeleteNode(user.ID, *id, false, tree.VersionUnchecked)
		return mcp.NewToolResultErrorf("Failed to set page content: %s", err.Error()), nil
	}

	return mcp.NewToolResultText("Page created: " + *id + " (" + title + ")"), nil
}

func (s *Server) handleUpdatePage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleEditor) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	id := req.GetString("id", "")
	if id == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	title := req.GetString("title", "")
	content := req.GetString("content", "")
	if title == "" && content == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	page, err := s.config.TreeSvc.GetPage(id)
	if page == nil {
		return mcp.NewToolResultError(ErrPageNotFound.Message), nil
	}

	newTitle := title
	if newTitle == "" {
		newTitle = page.Title
	}

	var contentPtr *string
	if content != "" {
		contentPtr = &content
	}

	err = s.config.TreeSvc.UpdateNode(user.ID, id, newTitle, page.Slug, contentPtr, tree.VersionUnchecked, false)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to update page: %s", err.Error()), nil
	}

	return mcp.NewToolResultText("Page updated: " + id), nil
}

func (s *Server) handleDeletePage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleEditor) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	id := req.GetString("id", "")
	if id == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	recursive := req.GetBool("recursive", false)

	err := s.config.TreeSvc.DeleteNode(user.ID, id, recursive, tree.VersionUnchecked)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to delete page: %s", err.Error()), nil
	}

	return mcp.NewToolResultText("Page deleted: " + id), nil
}

func (s *Server) handleMovePage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleEditor) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	id := req.GetString("id", "")
	parentID := req.GetString("parentID", "")
	if id == "" || parentID == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	err := s.config.TreeSvc.MoveNode(user.ID, id, parentID, tree.VersionUnchecked)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to move page: %s", err.Error()), nil
	}

	return mcp.NewToolResultText("Page moved: " + id + " to " + parentID), nil
}

func slugFromTitle(title string) string {
	s := ""
	for i, r := range title {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			s += string(r)
		} else if r >= 'A' && r <= 'Z' {
			if i > 0 {
				s += "-"
			}
			s += string(r + 32)
		} else {
			s += "-"
		}
	}
	// Collapse multiple dashes
	result := ""
	for _, c := range s {
		if c == '-' && len(result) > 0 && result[len(result)-1] == '-' {
			continue
		}
		result += string(c)
	}
	// Trim leading/trailing dashes
	for len(result) > 0 && result[0] == '-' {
		result = result[1:]
	}
	for len(result) > 0 && result[len(result)-1] == '-' {
		result = result[:len(result)-1]
	}
	return result
}
