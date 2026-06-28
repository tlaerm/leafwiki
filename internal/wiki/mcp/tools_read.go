package mcp

import (
	"context"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/perber/wiki/internal/core/auth"
	"github.com/perber/wiki/internal/core/tree"
)

func (s *Server) registerReadTools() {
	s.svc.AddTools(
		server.ServerTool{
			Tool: mcp.NewTool("get_page",
				mcp.WithDescription("Get a page by its ID, returning the page content as markdown."),
				mcp.WithString("id",
					mcp.Required(),
					mcp.Description("The ID of the page"),
				),
			),
			Handler: s.handleGetPage,
		},
		server.ServerTool{
			Tool: mcp.NewTool("get_page_by_path",
				mcp.WithDescription("Get a page by its route path (e.g. '/welcome-to-leafwiki')."),
				mcp.WithString("path",
					mcp.Required(),
					mcp.Description("The route path of the page"),
				),
			),
			Handler: s.handleGetPageByPath,
		},
		server.ServerTool{
			Tool: mcp.NewTool("search",
				mcp.WithDescription("Search pages by query text. Returns matching pages with excerpts."),
				mcp.WithString("query",
					mcp.Required(),
					mcp.Description("The search query"),
				),
				mcp.WithInteger("limit",
					mcp.Description("Maximum number of results (default 20)"),
				),
			),
			Handler: s.handleSearch,
		},
		server.ServerTool{
			Tool: mcp.NewTool("list_tree",
				mcp.WithDescription("List the full page tree structure. Returns all pages and sections with their IDs, titles, slugs, and kinds."),
			),
			Handler: s.handleListTree,
		},
		server.ServerTool{
			Tool: mcp.NewTool("get_page_revisions",
				mcp.WithDescription("Get the revision history for a page."),
				mcp.WithString("id",
					mcp.Required(),
					mcp.Description("The ID of the page"),
				),
			),
			Handler: s.handleGetPageRevisions,
		},
	)
}

func (s *Server) handleGetPage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleViewer) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	id := req.GetString("id", "")
	if id == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	page, err := s.config.TreeSvc.GetPage(id)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to get page: %s", err.Error()), nil
	}
	if page == nil {
		return mcp.NewToolResultError(ErrPageNotFound.Message), nil
	}

	return mcp.NewToolResultText(page.Content), nil
}

func (s *Server) handleGetPageByPath(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleViewer) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	path := req.GetString("path", "")
	if path == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}
	// Strip leading slash: "FindPageByRoutePath" splits on "/" and rejects empty parts.
	path = strings.TrimPrefix(path, "/")

	page, err := s.config.TreeSvc.FindPageByRoutePath(path)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to get page: %s", err.Error()), nil
	}
	if page == nil {
		return mcp.NewToolResultError(ErrPageNotFound.Message), nil
	}

	return mcp.NewToolResultText(page.Content), nil
}

func (s *Server) handleSearch(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleViewer) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	query := req.GetString("query", "")
	if query == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	limit := req.GetInt("limit", 20)

	result, err := s.config.SearchIndex.Search(query, nil, 0, limit)
	if err != nil {
		return mcp.NewToolResultErrorf("Search failed: %s", err.Error()), nil
	}

	var items []string
	for _, item := range result.Items {
		items = append(items, "- **"+item.Title+"** ("+item.Kind+") ["+item.PageID+"]\n  Path: "+item.Path+"\n  Excerpt: "+item.Excerpt)
	}

	if len(items) == 0 {
		return mcp.NewToolResultText("No results found."), nil
	}

	return mcp.NewToolResultText("Found " + itoa(result.Count) + " results:\n\n" + join(items, "\n\n")), nil
}

func (s *Server) handleListTree(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleViewer) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	root := s.config.TreeSvc.GetTree()
	if root == nil {
		return mcp.NewToolResultText("No pages found."), nil
	}

	lines := walkTree(root, 0)
	return mcp.NewToolResultText(join(lines, "\n")), nil
}

func (s *Server) handleGetPageRevisions(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user := userFromContext(ctx)
	if !userHasRole(user, auth.RoleViewer) {
		return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
	}

	id := req.GetString("id", "")
	if id == "" {
		return mcp.NewToolResultError(ErrInvalidInput.Message), nil
	}

	if s.config.RevisionSvc == nil {
		return mcp.NewToolResultError("Revisions are not enabled."), nil
	}

	revisions, err := s.config.RevisionSvc.ListRevisions(id)
	if err != nil {
		return mcp.NewToolResultErrorf("Failed to get revisions: %s", err.Error()), nil
	}

	if len(revisions) == 0 {
		return mcp.NewToolResultText("No revisions found."), nil
	}

	var items []string
	for _, r := range revisions {
		items = append(items, "- **"+r.ID+"** ("+string(r.Type)+") by "+r.AuthorID+" at "+r.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	return mcp.NewToolResultText("Revisions for page "+id+":\n\n" + join(items, "\n\n")), nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func userHasRole(user *auth.User, minRole string) bool {
	if user == nil {
		return false
	}
	switch minRole {
	case auth.RoleViewer:
		return true
	case auth.RoleEditor:
		return user.HasRole(auth.RoleEditor) || user.HasRole(auth.RoleAdmin)
	case auth.RoleAdmin:
		return user.HasRole(auth.RoleAdmin)
	}
	return false
}

func walkTree(node *tree.PageNode, depth int) []string {
	var lines []string
	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}
	line := indent + "- **" + node.Title + "** [" + node.ID + "] (" + string(node.Kind) + ") /" + node.Slug
	if node.Kind == tree.NodeKindPage && !node.Metadata.UpdatedAt.IsZero() {
		line += " (updated: " + node.Metadata.UpdatedAt.Format("2006-01-02 15:04:05") + ")"
	}
	lines = append(lines, line)
	for _, child := range node.Children {
		lines = append(lines, walkTree(child, depth+1)...)
	}
	return lines
}

func join(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}
