package auth

import (
	"testing"
	"time"

	"github.com/perber/wiki/internal/test_utils"
)

func setupTestAPIKeyService(t *testing.T) (*APIKeyService, *UserService) {
	t.Helper()
	dir := t.TempDir()

	apiKeyStore, err := NewAPIKeyStore(dir)
	if err != nil {
		t.Fatalf("failed to create api key store: %v", err)
	}
	t.Cleanup(func() {
		test_utils.WrapCloseWithErrorCheck(apiKeyStore.Close, t)
	})

	userStore, err := NewUserStore(dir)
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}
	t.Cleanup(func() {
		test_utils.WrapCloseWithErrorCheck(userStore.Close, t)
	})

	userSvc := NewUserService(userStore)
	apiKeySvc := NewAPIKeyService(apiKeyStore, userSvc)

	return apiKeySvc, userSvc
}

func createUserForTests(t *testing.T, svc *UserService) string {
	t.Helper()
	u, err := svc.CreateUser("testuser", "test@example.com", "password123", "editor")
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return u.ID
}

func TestAPIKeyService_Create(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	key, err := apiKeySvc.Create(userID, "my key", nil)
	if err != nil {
		t.Fatalf("failed to create api key: %v", err)
	}

	if key.Key == "" {
		t.Fatal("expected plaintext key to be returned")
	}
	if key.Name != "my key" {
		t.Errorf("expected name 'my key', got %s", key.Name)
	}
	if key.UserID != userID {
		t.Errorf("expected userID %s, got %s", userID, key.UserID)
	}
	if key.ExpiresAt != nil {
		t.Error("expected nil expires_at")
	}

	// ID should be a short ID, not a 64-char SHA-256 hash
	if len(key.ID) > 30 {
		t.Errorf("expected short ID, got %s (len %d)", key.ID, len(key.ID))
	}
}

func TestAPIKeyService_CreateWithExpiration(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	expiresAt := time.Now().Add(24 * time.Hour)
	key, err := apiKeySvc.Create(userID, "expiring key", &expiresAt)
	if err != nil {
		t.Fatalf("failed to create api key: %v", err)
	}

	if key.ExpiresAt == nil {
		t.Fatal("expected non-nil expires_at")
	}
}

func TestAPIKeyService_Authenticate(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	key, err := apiKeySvc.Create(userID, "auth key", nil)
	if err != nil {
		t.Fatalf("failed to create api key: %v", err)
	}

	user, err := apiKeySvc.Authenticate(key.Key)
	if err != nil {
		t.Fatalf("failed to authenticate: %v", err)
	}

	if user.ID != userID {
		t.Errorf("expected userID %s, got %s", userID, user.ID)
	}
}

func TestAPIKeyService_AuthenticateInvalidKey(t *testing.T) {
	apiKeySvc, _ := setupTestAPIKeyService(t)

	_, err := apiKeySvc.Authenticate("lw_invalidkey")
	if err != ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

func TestAPIKeyService_AuthenticateMalformedKey(t *testing.T) {
	apiKeySvc, _ := setupTestAPIKeyService(t)

	_, err := apiKeySvc.Authenticate("not-a-valid-key")
	if err != ErrAPIKeyMalformed {
		t.Errorf("expected ErrAPIKeyMalformed, got %v", err)
	}

	_, err = apiKeySvc.Authenticate("")
	if err != ErrAPIKeyMalformed {
		t.Errorf("expected ErrAPIKeyMalformed for empty key, got %v", err)
	}
}

func TestAPIKeyService_AuthenticateRevokedKey(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	key, err := apiKeySvc.Create(userID, "revoked key", nil)
	if err != nil {
		t.Fatalf("failed to create api key: %v", err)
	}

	err = apiKeySvc.Revoke(key.ID, userID)
	if err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	_, err = apiKeySvc.Authenticate(key.Key)
	if err != ErrAPIKeyRevoked {
		t.Errorf("expected ErrAPIKeyRevoked, got %v", err)
	}
}

func TestAPIKeyService_AuthenticateExpiredKey(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	expiresAt := time.Now().Add(-1 * time.Hour)
	key, err := apiKeySvc.Create(userID, "expired key", &expiresAt)
	if err != nil {
		t.Fatalf("failed to create api key: %v", err)
	}

	_, err = apiKeySvc.Authenticate(key.Key)
	if err != ErrAPIKeyExpired {
		t.Errorf("expected ErrAPIKeyExpired, got %v", err)
	}
}

func TestAPIKeyService_List(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	_, err := apiKeySvc.Create(userID, "key 1", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	_, err = apiKeySvc.Create(userID, "key 2", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	keys, err := apiKeySvc.List(userID)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestAPIKeyService_Revoke(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	key, err := apiKeySvc.Create(userID, "to revoke", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	err = apiKeySvc.Revoke(key.ID, userID)
	if err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	_, err = apiKeySvc.Authenticate(key.Key)
	if err != ErrAPIKeyRevoked {
		t.Errorf("expected ErrAPIKeyRevoked after revoke, got %v", err)
	}
}

func TestAPIKeyService_ListExcludesRevoked(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	_, err := apiKeySvc.Create(userID, "key 1", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	key2, err := apiKeySvc.Create(userID, "key 2", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	_, err = apiKeySvc.Create(userID, "key 3", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	err = apiKeySvc.Revoke(key2.ID, userID)
	if err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	keys, err := apiKeySvc.List(userID)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("expected 2 keys (revoked excluded), got %d", len(keys))
	}
}

func TestAPIKeyService_RevokeWrongOwner(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)
	otherUser, err := userSvc.CreateUser("otheruser", "other@example.com", "password123", "editor")
	if err != nil {
		t.Fatalf("failed to create other user: %v", err)
	}

	key, err := apiKeySvc.Create(userID, "other key", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	err = apiKeySvc.Revoke(key.ID, otherUser.ID)
	if err != ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound when revoking another user's key, got %v", err)
	}
}

func TestAPIKeyService_DeleteByUser(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	_, err := apiKeySvc.Create(userID, "key 1", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	err = apiKeySvc.DeleteByUser(userID)
	if err != nil {
		t.Fatalf("failed to delete by user: %v", err)
	}

	keys, err := apiKeySvc.List(userID)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestAPIKeyService_CreateLimitExceeded(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	// Create up to the limit
	for i := 0; i < MaxAPIKeysPerUser; i++ {
		_, err := apiKeySvc.Create(userID, "key", nil)
		if err != nil {
			t.Fatalf("failed to create key %d (below limit): %v", i, err)
		}
	}

	// Next one should fail
	_, err := apiKeySvc.Create(userID, "too many", nil)
	if err != ErrAPIKeyLimitExceeded {
		t.Errorf("expected ErrAPIKeyLimitExceeded, got %v", err)
	}
}

func TestAPIKeyService_CreateLimitAllowsAfterRevoke(t *testing.T) {
	apiKeySvc, userSvc := setupTestAPIKeyService(t)
	userID := createUserForTests(t, userSvc)

	// Create up to the limit
	for i := 0; i < MaxAPIKeysPerUser; i++ {
		_, err := apiKeySvc.Create(userID, "key", nil)
		if err != nil {
			t.Fatalf("failed to create key %d: %v", i, err)
		}
	}

	// Last one should have failed above, now revoke one
	keys, err := apiKeySvc.List(userID)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	if len(keys) != MaxAPIKeysPerUser {
		t.Fatalf("expected %d keys, got %d", MaxAPIKeysPerUser, len(keys))
	}

	err = apiKeySvc.Revoke(keys[0].ID, userID)
	if err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	// Now one more should succeed
	_, err = apiKeySvc.Create(userID, "replaced", nil)
	if err != nil {
		t.Errorf("expected key creation to succeed after revoke, got: %v", err)
	}
}
