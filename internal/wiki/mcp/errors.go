package mcp

import "fmt"

type ToolError struct {
	Code    string
	Message string
}

func (e *ToolError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Message
}

var (
	ErrPageNotFound      = &ToolError{Code: "page_not_found", Message: "Page not found"}
	ErrInsufficientRole  = &ToolError{Code: "insufficient_role", Message: "Insufficient role"}
	ErrInvalidInput      = &ToolError{Code: "invalid_input", Message: "Invalid input"}
	ErrUserNotFound      = &ToolError{Code: "user_not_found", Message: "User not found"}
	ErrPathInvalid       = &ToolError{Code: "path_invalid", Message: "Invalid path format"}
	ErrPathAlreadyExists = &ToolError{Code: "path_already_exists", Message: "Path already exists"}
	ErrConvertNotAllowed = &ToolError{Code: "convert_not_allowed", Message: "Cannot convert: node has children or is root"}
)
