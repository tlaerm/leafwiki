package mcp

import (
	"context"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/perber/wiki/internal/core/auth"
	"github.com/perber/wiki/internal/core/tree"
)

func (s *Server) registerWriteTools() {
	s.svc.AddTools(
		server.ServerTool{
			Tool: mcp.NewTool("create_page",
				mcp.WithDescription("Create a new page or section. Requires editor or admin role."),
				mcp.WithString("title",
					mcp.Required(),
					mcp.Description("The title of the page/section"),
				),
				mcp.WithString("content",
					mcp.Description("The markdown content of the page (required for kind='page')"),
				),
				mcp.WithString("parentID",
					mcp.Description("The ID of the parent section (optional, creates at root if omitted)"),
				),
				mcp.WithString("kind",
					mcp.Description("Node kind: 'page' or 'section'. Default: 'page'"),
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
		server.ServerTool{
			Tool: mcp.NewTool("ensure_path",
				mcp.WithDescription("Ensure a full path exists, creating intermediate nodes as needed. Requires editor or admin role."),
				mcp.WithString("path",
					mcp.Required(),
					mcp.Description("The full path (e.g., '/homelab/projects/my-project')"),
				),
				mcp.WithString("title",
					mcp.Required(),
					mcp.Description("The title for the final node"),
				),
				mcp.WithString("kind",
					mcp.Description("Node kind for final node: 'page' or 'section'. Default: 'page'"),
				),
				mcp.WithString("content",
					mcp.Description("Content for the final page (only if kind='page')"),
				),
			),
			Handler: s.handleEnsurePath,
		},
		server.ServerTool{
			Tool: mcp.NewTool("convert_node",
				mcp.WithDescription("Convert a page/section to a different node kind (page ↔ section). Requires editor or admin role."),
				mcp.WithString("id",
					mcp.Required(),
					mcp.Description("The ID of the page/section to convert"),
				),
				mcp.WithString("kind",
					mcp.Required(),
					mcp.Description("Target kind: 'page' or 'section'"),
				),
			),
			Handler: s.handleConvertNode,
		},
		server.ServerTool{
			Tool: mcp.NewTool("copy_page",
				mcp.WithDescription("Copy a page and its assets to a new location. Requires editor or admin role."),
				mcp.WithString("sourceID",
					mcp.Required(),
					mcp.Description("The ID of the page to copy"),
				),
				mcp.WithString("title",
					mcp.Required(),
					mcp.Description("The title for the new page"),
				),
				mcp.WithString("parentID",
					mcp.Description("The ID of the parent section (optional, creates at root if omitted)"),
				),
			),
			Handler: s.handleCopyPage,
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
	parentID := req.GetString("parentID", "")
	kindStr := req.GetString("kind", "page")

	if title == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	// Validate kind
	var kind tree.NodeKind
	switch kindStr {
	case "section":
		kind = tree.NodeKindSection
	case "page":
		kind = tree.NodeKindPage
	default:
		return mcp.NewToolResultError("Invalid kind: must be 'page' or 'section'"), nil
	}

	// Content is required for pages
	if kind == tree.NodeKindPage && content == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	slug := slugFromTitle(title)

	var pID *string
	if parentID != "" {
		pID = &parentID
	}

	id, err := s.config.TreeSvc.CreateNode(user.ID, pID, title, slug, &kind)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to create %s: %s", kindStr, err.Error()), nil
	}

	// Set content only for pages
	if kind == tree.NodeKindPage && content != "" {
		err = s.config.TreeSvc.UpdateNode(user.ID, *id, title, slug, &content, tree.VersionUnchecked, false)
		if err != nil {
			s.config.TreeSvc.DeleteNode(user.ID, *id, false, tree.VersionUnchecked)
			return mcp.NewToolResultErrorf("Failed to set page content: %s", err.Error()), nil
		}
	}

	return mcp.NewToolResultText(kindStr + " created: " + *id + " (" + title + ")"), nil
}

func (s *Server) handleEnsurePath(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleEditor) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	path := req.GetString("path", "")
	title := req.GetString("title", "")
	kindStr := req.GetString("kind", "page")
	content := req.GetString("content", "")

	if path == "" || title == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	// Validate path format
	path = strings.TrimRight(path, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 && strings.Contains(path, "..") {
		return mcp.NewToolResultError(ErrPathInvalid.Message), nil
	}

	// Validate kind
	var kind tree.NodeKind
	switch kindStr {
	case "section":
		kind = tree.NodeKindSection
	case "page":
		kind = tree.NodeKindPage
	default:
		return mcp.NewToolResultError("Invalid kind: must be 'page' or 'section'"), nil
	}

	// Content is required for pages
	if kind == tree.NodeKindPage && content == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	result, err := s.config.TreeSvc.EnsurePagePath(user.ID, path, title, &kind)
	if err != nil {
		if result != nil && result.Exists && result.Page != nil {
			return mcp.NewToolResultError(ErrPathAlreadyExists.Message), nil
		}
		return mcp.NewToolResultErrorf("Failed to ensure path: %s", err.Error()), nil
	}

	if result == nil || result.Page == nil {
		return mcp.NewToolResultError("Failed to ensure path: no page created"), nil
	}

	pageID := result.Page.ID
	pageSlug := result.Page.Slug

	// Set content only for pages
	if kind == tree.NodeKindPage && content != "" {
		err = s.config.TreeSvc.UpdateNode(user.ID, pageID, title, pageSlug, &content, tree.VersionUnchecked, false)
		if err != nil {
			return mcp.NewToolResultErrorf("Failed to set page content: %s", err.Error()), nil
		}
	}

	return mcp.NewToolResultText("Path ensured: " + path + " -> " + title + " (" + pageID + ")"), nil
}

func (s *Server) handleConvertNode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleEditor) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	id := req.GetString("id", "")
	kindStr := req.GetString("kind", "")

	if id == "" || kindStr == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	var kind tree.NodeKind
	switch kindStr {
	case "page":
		kind = tree.NodeKindPage
	case "section":
		kind = tree.NodeKindSection
	default:
		return mcp.NewToolResultError("Invalid kind: must be 'page' or 'section'"), nil
	}

	err := s.config.TreeSvc.ConvertNode(user.ID, id, kind, tree.VersionUnchecked)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to convert: %s", err.Error()), nil
	}

	return mcp.NewToolResultText("Converted " + id + " to " + kindStr), nil
}

func (s *Server) handleCopyPage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleEditor) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	sourceID := req.GetString("sourceID", "")
	title := req.GetString("title", "")
	parentID := req.GetString("parentID", "")

	if sourceID == "" || title == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	slug := slugFromTitle(title)

	// Get source page
	sourcePage, err := s.config.TreeSvc.GetPage(sourceID)
	if err != nil {
		return mcp.NewToolResultErrorf("Source page not found: %s", err.Error()), nil
	}

	// Create new node
	kind := tree.NodeKindPage
	var pID *string
	if parentID != "" {
		pID = &parentID
	}

	id, err := s.config.TreeSvc.CreateNode(user.ID, pID, title, slug, &kind)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to create page: %s", err.Error()), nil
	}

	// Get new page
	newPage, err := s.config.TreeSvc.GetPage(*id)
	if err != nil {
		s.config.TreeSvc.DeleteNode(user.ID, *id, false, tree.VersionUnchecked)
		return mcp.NewToolResultErrorf("Failed to get new page: %s", err.Error()), nil
	}

	// Copy assets if asset service is available
	if s.config.AssetSvc != nil {
		err = s.config.AssetSvc.CopyAllAssets(sourcePage.PageNode, newPage.PageNode)
		if err != nil {
			s.config.TreeSvc.DeleteNode(user.ID, *id, false, tree.VersionUnchecked)
			return mcp.NewToolResultErrorf("Failed to copy assets: %s", err.Error()), nil
		}
	}

	return mcp.NewToolResultText("Page copied: " + *id + " (" + title + ")"), nil
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
