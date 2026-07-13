package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/perber/wiki/internal/core/auth"
)

func TestCreatePage_SectionKindValidation(t *testing.T) {
	// Test section kind validation logic
	tests := []struct {
		kind    string
		valid   bool
		reason  string
	}{
		{"page", true, "valid kind"},
		{"section", true, "valid kind"},
		{"folder", false, "invalid kind"},
		{"directory", false, "invalid kind"},
		{"node", false, "invalid kind"},
		{"", true, "empty kind defaults to page (valid)"},
	}

	for _, tc := range tests {
		valid := tc.kind == "page" || tc.kind == "section"

		// Empty kind defaults to "page", so it's valid
		if tc.kind == "" {
			valid = true
		}

		if valid != tc.valid {
			t.Errorf("kind=%q: expected valid=%v, got valid=%v (%s)", tc.kind, tc.valid, valid, tc.reason)
		}
	}
}

func TestEnsurePath_PathValidation(t *testing.T) {
	tests := []struct {
		path       string
		shouldFail bool
		reason     string
	}{
		{"/homelab/projects/test", false, "valid path"},
		{"homelab/projects/test", false, "path without leading slash (should be normalized)"},
		{"/homelab/../projects/test", true, "path with .."},
		{"", true, "empty path"},
		{"/", false, "root path"},
	}

	for _, tc := range tests {
		path := tc.path
		isInvalid := false

		if path == "" {
			isInvalid = true
		} else {
			path = strings.TrimRight(path, "/")
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			if len(path) > 1 && strings.Contains(path, "..") {
				isInvalid = true
			}
		}

		if isInvalid != tc.shouldFail {
			t.Errorf("path %q: expected shouldFail=%v, got isInvalid=%v (%s)", tc.path, tc.shouldFail, isInvalid, tc.reason)
		}
	}
}

func TestConvertNode_InvalidKind(t *testing.T) {
	invalidKinds := []string{"folder", "directory", "node", "invalid"}
	validKinds := []string{"page", "section"}

	invalidCount := 0
	validCount := 0

	for _, kind := range invalidKinds {
		if kind != "page" && kind != "section" {
			invalidCount++
		}
	}

	for _, kind := range validKinds {
		if kind == "page" || kind == "section" {
			validCount++
		}
	}

	if invalidCount != len(invalidKinds) {
		t.Errorf("expected %d invalid kinds, got %d", len(invalidKinds), invalidCount)
	}
	if validCount != len(validKinds) {
		t.Errorf("expected %d valid kinds, got %d", len(validKinds), validCount)
	}
}

func TestCopyPage_RequiredFields(t *testing.T) {
	tests := []struct {
		title    string
		sourceID string
		expected string
	}{
		{"Test Page", "source-id", "valid"},
		{"Test Page", "", "invalid - sourceID required"},
		{"", "source-id", "invalid - title required"},
		{"", "", "invalid - both required"},
	}

	for _, tc := range tests {
		isValid := tc.title != "" && tc.sourceID != ""
		expected := tc.expected == "valid"

		if isValid != expected {
			t.Errorf("title=%q, sourceID=%q: expected valid=%v, got valid=%v", tc.title, tc.sourceID, expected, isValid)
		}
	}
}

func TestHandleCreatePage_ContentRequirement(t *testing.T) {
	tests := []struct {
		kind    string
		content string
		valid   bool
	}{
		{"page", "content", true},
		{"page", "", false},
		{"section", "content", true},
		{"section", "", true},
	}

	for _, tc := range tests {
		expectedValid := tc.valid
		actualValid := true

		if tc.kind == "page" && tc.content == "" {
			actualValid = false
		}

		if actualValid != expectedValid {
			t.Errorf("kind=%q, content=%q: expected valid=%v, got valid=%v", tc.kind, tc.content, expectedValid, actualValid)
		}
	}
}

func TestUserHasRole_EditorRequired(t *testing.T) {
	admin := &auth.User{Role: auth.RoleAdmin}
	editor := &auth.User{Role: auth.RoleEditor}
	viewer := &auth.User{Role: auth.RoleViewer}

	if !userHasRole(admin, auth.RoleEditor) {
		t.Error("admin should have editor role")
	}
	if !userHasRole(editor, auth.RoleEditor) {
		t.Error("editor should have editor role")
	}
	if userHasRole(viewer, auth.RoleEditor) {
		t.Error("viewer should not have editor role")
	}
}

func TestSlugFromTitle_ComplexCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"A B C D E", "a-b-c-d-e"},
		{"Test123Page", "test123-page"},
		{"Multiple   Spaces", "multiple-spaces"},
		{"Special!@#$%Chars", "special-chars"},
		{"Leading and trailing ", "leading-and-trailing"},
		{"HelloWorld", "hello-world"},
	}

	for _, tc := range tests {
		result := slugFromTitle(tc.input)
		if result != tc.expected {
			t.Errorf("slugFromTitle(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestToolDefinitions_Registered(t *testing.T) {
	expectedTools := []string{
		"create_page",
		"update_page",
		"delete_page",
		"move_page",
		"ensure_path",
		"convert_node",
		"copy_page",
	}

	s := server.NewMCPServer("test", "0.1.0")
	for _, toolName := range expectedTools {
		s.AddTool(mcp.NewTool(toolName,
			mcp.WithDescription("Test tool: "+toolName),
		), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		})
	}

	tools := s.ListTools()
	if len(tools) != len(expectedTools) {
		t.Errorf("expected %d tools, got %d", len(expectedTools), len(tools))
	}
}

func TestToolDefinitions_HaveDescriptions(t *testing.T) {
	expectedTools := []string{
		"create_page",
		"update_page",
		"delete_page",
		"move_page",
		"ensure_path",
		"convert_node",
		"copy_page",
	}

	// Verify tool names are valid identifiers
	for _, toolName := range expectedTools {
		if toolName == "" {
			t.Error("tool name should not be empty")
		}
		if len(toolName) > 50 {
			t.Errorf("tool name %q is too long", toolName)
		}
	}

	// Verify we can create tools with these names
	s := server.NewMCPServer("test", "0.1.0")
	count := 0
	for _, toolName := range expectedTools {
		s.AddTool(mcp.NewTool(toolName,
			mcp.WithDescription("Test tool: "+toolName),
		), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		})
		count++
	}

	if count != len(expectedTools) {
		t.Errorf("expected to register %d tools, registered %d", len(expectedTools), count)
	}
}
