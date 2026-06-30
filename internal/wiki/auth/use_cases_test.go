package auth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	coreauth "github.com/perber/wiki/internal/core/auth"
)

func setupUpdateUserUseCase(t *testing.T) (*UpdateUserUseCase, *coreauth.UserService) {
	t.Helper()
	store, err := coreauth.NewUserStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	userSvc := coreauth.NewUserService(store)
	resolver, err := coreauth.NewUserResolver(userSvc)
	if err != nil {
		t.Fatalf("NewUserResolver: %v", err)
	}
	return NewUpdateUserUseCase(userSvc, resolver, slog.Default()), userSvc
}

// TestUpdateUser_AdminCanChangeRole verifies that an admin requester can promote
// or demote another user's role.
func TestUpdateUser_AdminCanChangeRole(t *testing.T) {
	uc, svc := setupUpdateUserUseCase(t)

	viewer, err := svc.CreateUser("viewer", "viewer@example.com", "pass", coreauth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	out, err := uc.Execute(context.Background(), UpdateUserInput{
		ID:               viewer.ID,
		Username:         viewer.Username,
		Email:            viewer.Email,
		Role:             coreauth.RoleAdmin,
		RequesterIsAdmin: true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.User.Role != coreauth.RoleAdmin {
		t.Errorf("expected role %q, got %q", coreauth.RoleAdmin, out.User.Role)
	}
}

// TestUpdateUser_AdminCanUpdateProfileWithoutRole verifies that an admin can
// update username/email without sending a role and the existing role is kept.
func TestUpdateUser_AdminCanUpdateProfileWithoutRole(t *testing.T) {
	uc, svc := setupUpdateUserUseCase(t)

	editor, err := svc.CreateUser("ed", "ed@example.com", "pass", coreauth.RoleEditor)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	out, err := uc.Execute(context.Background(), UpdateUserInput{
		ID:               editor.ID,
		Username:         "ed-admin-updated",
		Email:            "ed-admin-updated@example.com",
		Role:             "",
		RequesterIsAdmin: true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.User.Username != "ed-admin-updated" {
		t.Errorf("expected username %q, got %q", "ed-admin-updated", out.User.Username)
	}
	if out.User.Email != "ed-admin-updated@example.com" {
		t.Errorf("expected email %q, got %q", "ed-admin-updated@example.com", out.User.Email)
	}
	if out.User.Role != coreauth.RoleEditor {
		t.Errorf("expected role %q, got %q", coreauth.RoleEditor, out.User.Role)
	}
}

// TestUpdateUser_NonAdminCannotEscalateRole is the regression test for
// GHSA-jj4r-587p-r5h5: a viewer calling PUT /api/users/:id on their own account
// must not be able to promote themselves to admin.
func TestUpdateUser_NonAdminCannotEscalateRole(t *testing.T) {
	uc, svc := setupUpdateUserUseCase(t)

	viewer, err := svc.CreateUser("viewer", "viewer@example.com", "pass", coreauth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	out, err := uc.Execute(context.Background(), UpdateUserInput{
		ID:               viewer.ID,
		Username:         viewer.Username,
		Email:            viewer.Email,
		Role:             coreauth.RoleAdmin, // attacker sends "admin"
		RequesterIsAdmin: false,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.User.Role != coreauth.RoleViewer {
		t.Errorf("role escalation succeeded: expected %q, got %q", coreauth.RoleViewer, out.User.Role)
	}
}

// TestUpdateUser_NonAdminCanUpdateOwnProfile verifies that non-admin users can
// still change their username and email while their role stays unchanged.
func TestUpdateUser_NonAdminCanUpdateOwnProfile(t *testing.T) {
	uc, svc := setupUpdateUserUseCase(t)

	editor, err := svc.CreateUser("ed", "ed@example.com", "pass", coreauth.RoleEditor)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	out, err := uc.Execute(context.Background(), UpdateUserInput{
		ID:               editor.ID,
		Username:         "ed-updated",
		Email:            "ed-updated@example.com",
		Role:             coreauth.RoleAdmin, // should be silently ignored
		RequesterIsAdmin: false,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.User.Username != "ed-updated" {
		t.Errorf("expected username %q, got %q", "ed-updated", out.User.Username)
	}
	if out.User.Email != "ed-updated@example.com" {
		t.Errorf("expected email %q, got %q", "ed-updated@example.com", out.User.Email)
	}
	if out.User.Role != coreauth.RoleEditor {
		t.Errorf("role must not change: expected %q, got %q", coreauth.RoleEditor, out.User.Role)
	}
}

// TestUpdateUser_LastAdminCannotSelfDemote verifies that the last admin cannot
// demote themselves, which would leave the system with no admins.
func TestUpdateUser_LastAdminCannotSelfDemote(t *testing.T) {
	uc, svc := setupUpdateUserUseCase(t)

	admin, err := svc.CreateUser("admin", "admin@example.com", "pass", coreauth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = uc.Execute(context.Background(), UpdateUserInput{
		ID:               admin.ID,
		Username:         admin.Username,
		Email:            admin.Email,
		Role:             coreauth.RoleViewer,
		RequesterIsAdmin: true,
	})
	if !errors.Is(err, coreauth.ErrLastAdminCannotBeDemoted) {
		t.Errorf("expected ErrLastAdminCannotBeDemoted, got: %v", err)
	}
}

// TestUpdateUser_AdminCanBeDemotedWhenAnotherExists verifies that an admin can
// lose their role as long as at least one other admin remains.
func TestUpdateUser_AdminCanBeDemotedWhenAnotherExists(t *testing.T) {
	uc, svc := setupUpdateUserUseCase(t)

	admin1, _ := svc.CreateUser("admin1", "admin1@example.com", "pass", coreauth.RoleAdmin)
	_, _ = svc.CreateUser("admin2", "admin2@example.com", "pass", coreauth.RoleAdmin)

	out, err := uc.Execute(context.Background(), UpdateUserInput{
		ID:               admin1.ID,
		Username:         admin1.Username,
		Email:            admin1.Email,
		Role:             coreauth.RoleViewer,
		RequesterIsAdmin: true,
	})
	if err != nil {
		t.Fatalf("expected demotion to succeed, got: %v", err)
	}
	if out.User.Role != coreauth.RoleViewer {
		t.Errorf("expected role %q, got %q", coreauth.RoleViewer, out.User.Role)
	}
}

// TestUpdateUser_AdminInvalidRole checks that an admin supplying an unknown role
// gets a validation error rather than storing garbage.
func TestUpdateUser_AdminInvalidRole(t *testing.T) {
	uc, svc := setupUpdateUserUseCase(t)

	user, err := svc.CreateUser("alice", "alice@example.com", "pass", coreauth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err = uc.Execute(context.Background(), UpdateUserInput{
		ID:               user.ID,
		Username:         user.Username,
		Email:            user.Email,
		Role:             "superuser", // not a valid role
		RequesterIsAdmin: true,
	})
	if err == nil {
		t.Fatal("expected validation error for invalid role, got nil")
	}
}

// TestAPIKeyNameMaxLengthValidation verifies that API key names longer than 100
// characters are rejected by the gin binding validator.
func TestAPIKeyNameMaxLengthValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 101 character name — exceeds the max=100 limit
	longName := strings.Repeat("x", 101)

	var req struct {
		Name string `json:"name" binding:"required,max=100"`
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"name": "`+longName+`"}`)))
	c.Request.Header.Set("Content-Type", "application/json")

	if err := c.ShouldBindWith(&req, binding.JSON); err == nil {
		t.Fatal("expected validation error for name > 100 characters, got nil")
	}

	// Exactly 100 characters should pass
	exactName := strings.Repeat("x", 100)
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"name": "`+exactName+`"}`)))
	c2.Request.Header.Set("Content-Type", "application/json")

	var req2 struct {
		Name string `json:"name" binding:"required,max=100"`
	}
	if err := c2.ShouldBindWith(&req2, binding.JSON); err != nil {
		t.Fatalf("expected 100-char name to pass validation, got error: %v", err)
	}
}

func TestParseDuration_RejectsSeconds(t *testing.T) {
	_, err := parseDuration("30s")
	if err == nil {
		t.Fatal("expected error for seconds unit, got nil")
	}
}

func TestParseDuration_RejectsZeroDuration(t *testing.T) {
	_, err := parseDuration("0h")
	if err == nil {
		t.Fatal("expected error for zero duration, got nil")
	}
}

func TestParseDuration_RejectsNegativeDuration(t *testing.T) {
	_, err := parseDuration("-1h")
	if err == nil {
		t.Fatal("expected error for negative duration, got nil")
	}
}

func TestParseDuration_ValidUnits(t *testing.T) {
	valid := map[string]time.Duration{
		"1h":  1 * time.Hour,
		"24h": 24 * time.Hour,
		"1d":  24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"1w":  7 * 24 * time.Hour,
		"1m":  30 * 24 * time.Hour,
		"1y":  365 * 24 * time.Hour,
	}
	for input, want := range valid {
		got, err := parseDuration(input)
		if err != nil {
			t.Errorf("parseDuration(%q): unexpected error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("parseDuration(%q): expected %v, got %v", input, want, got)
		}
	}
}
