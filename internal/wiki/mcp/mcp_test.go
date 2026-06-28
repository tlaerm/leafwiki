package mcp

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/perber/wiki/internal/core/auth"
)

func TestUserHasRole(t *testing.T) {
	admin := &auth.User{Role: auth.RoleAdmin}
	editor := &auth.User{Role: auth.RoleEditor}
	viewer := &auth.User{Role: auth.RoleViewer}

	if !userHasRole(admin, auth.RoleViewer) {
		t.Error("admin should have viewer role")
	}
	if !userHasRole(admin, auth.RoleEditor) {
		t.Error("admin should have editor role")
	}
	if !userHasRole(admin, auth.RoleAdmin) {
		t.Error("admin should have admin role")
	}

	if !userHasRole(editor, auth.RoleViewer) {
		t.Error("editor should have viewer role")
	}
	if !userHasRole(editor, auth.RoleEditor) {
		t.Error("editor should have editor role")
	}
	if userHasRole(editor, auth.RoleAdmin) {
		t.Error("editor should not have admin role")
	}

	if !userHasRole(viewer, auth.RoleViewer) {
		t.Error("viewer should have viewer role")
	}
	if userHasRole(viewer, auth.RoleEditor) {
		t.Error("viewer should not have editor role")
	}
	if userHasRole(viewer, auth.RoleAdmin) {
		t.Error("viewer should not have admin role")
	}

	if userHasRole(nil, auth.RoleViewer) {
		t.Error("nil user should not have viewer role")
	}
}

func TestToolError(t *testing.T) {
	err := ErrPageNotFound
	if err.Error() != "page_not_found: Page not found" {
		t.Errorf("expected 'page_not_found: Page not found', got '%s'", err.Error())
	}

	err2 := &ToolError{Message: "custom error"}
	if err2.Error() != "custom error" {
		t.Errorf("expected 'custom error', got '%s'", err2.Error())
	}
}

func TestSlugFromTitle(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello World", "hello-world"},
		{"Hello World!", "hello-world"},
		{"Hello   World", "hello-world"},
		{"Hello_World", "hello-world"},
		{"HelloWorld", "hello-world"},
		{"Hello123", "hello123"},
		{"---Hello---", "hello"},
		{"A B C", "a-b-c"},
		{"", ""},
	}

	for _, tc := range tests {
		result := slugFromTitle(tc.input)
		if result != tc.expected {
			t.Errorf("slugFromTitle(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestJoin(t *testing.T) {
	if join([]string{}, "-") != "" {
		t.Error("empty join should return empty string")
	}
	if join([]string{"a"}, "-") != "a" {
		t.Error("single element join")
	}
	if join([]string{"a", "b"}, "-") != "a-b" {
		t.Error("two element join")
	}
	if join([]string{"a", "b", "c"}, ",") != "a,b,c" {
		t.Error("three element join")
	}
}

func TestItoa(t *testing.T) {
	for i := 0; i < 100; i++ {
		result := itoa(i)
		expected := itoaSimple(i)
		if result != expected {
			t.Errorf("itoa(%d) = %q, want %q", i, result, expected)
		}
	}
}

func itoaSimple(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestServerMountReturnsHandler(t *testing.T) {
	s := New(Config{
		Name:    "TestWiki",
		Version: "0.1.0",
	})
	handler := s.Mount()
	if handler == nil {
		t.Error("Mount() should return a non-nil handler")
	}
}

func TestServerWithContextAuth(t *testing.T) {
	s := New(Config{
		Name:        "TestWiki",
		Version:     "0.1.0",
		APIKeySvc:   nil,
	})

	ctx := s.httpContextFunc(context.Background(), httptest.NewRequest("GET", "/", nil))
	if userFromContext(ctx) != nil {
		t.Error("should not have user in context without API key service")
	}
}

func TestGetPageToolInsufficientRole(t *testing.T) {
	svc := server.NewMCPServer("test", "0.1.0")
	svc.AddTool(mcp.NewTool("get_page",
		mcp.WithDescription("Test tool"),
		mcp.WithString("id", mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		user := userFromContext(ctx)
		if !userHasRole(user, auth.RoleViewer) {
			return mcp.NewToolResultError(ErrInsufficientRole.Message), nil
		}
		return mcp.NewToolResultText("ok"), nil
	})

	result := svc.ListTools()
	if len(result) != 1 {
		t.Errorf("expected 1 tool, got %d", len(result))
	}
}


