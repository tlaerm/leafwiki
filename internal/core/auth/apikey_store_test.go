package auth

import (
	"testing"
	"time"

	"github.com/perber/wiki/internal/test_utils"
)

func setupTestAPIKeyStore(t *testing.T) *APIKeyStore {
	t.Helper()
	store, err := NewAPIKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create api key store: %v", err)
	}
	t.Cleanup(func() {
		test_utils.WrapCloseWithErrorCheck(store.Close, t)
	})
	return store
}

func TestAPIKeyStore_CreateAndFind(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	keyID := "$2a$10$abcdefghijklmnop"
	err := store.Create(keyID, "user-1", "test key", nil)
	if err != nil {
		t.Fatalf("failed to create api key: %v", err)
	}

	row, err := store.FindByKeyHash(keyID)
	if err != nil {
		t.Fatalf("failed to find api key: %v", err)
	}

	if row.ID != keyID {
		t.Errorf("expected id %s, got %s", keyID, row.ID)
	}
	if row.UserID != "user-1" {
		t.Errorf("expected userID user-1, got %s", row.UserID)
	}
	if row.Name != "test key" {
		t.Errorf("expected name 'test key', got %s", row.Name)
	}
	if row.ExpiresAt != nil {
		t.Errorf("expected nil expires_at, got %v", row.ExpiresAt)
	}
	if row.RevokedAt != nil {
		t.Errorf("expected nil revoked_at, got %v", row.RevokedAt)
	}
}

func TestAPIKeyStore_CreateWithExpiration(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	expiresAt := time.Now().Add(24 * time.Hour)
	err := store.Create("key-id", "user-1", "expiring key", &expiresAt)
	if err != nil {
		t.Fatalf("failed to create api key: %v", err)
	}

	row, err := store.FindByKeyHash("key-id")
	if err != nil {
		t.Fatalf("failed to find api key: %v", err)
	}

	if row.ExpiresAt == nil {
		t.Fatal("expected non-nil expires_at")
	}
}

func TestAPIKeyStore_FindNotFound(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	_, err := store.FindByKeyHash("nonexistent")
	if err != ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

func TestAPIKeyStore_ListByUser(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	err := store.Create("key-1", "user-1", "first", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	err = store.Create("key-2", "user-1", "second", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	err = store.Create("key-3", "user-2", "other user", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	keys, err := store.ListByUser("user-1")
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestAPIKeyStore_Revoke(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	err := store.Create("key-id", "user-1", "to revoke", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	err = store.Revoke("key-id")
	if err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	row, err := store.FindByKeyHash("key-id")
	if err != nil {
		t.Fatalf("failed to find key: %v", err)
	}

	if row.RevokedAt == nil {
		t.Fatal("expected revoked_at to be set")
	}
}

func TestAPIKeyStore_RevokeNotFound(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	err := store.Revoke("nonexistent")
	if err != ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

func TestAPIKeyStore_RevokeAlreadyRevoked(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	err := store.Create("key-id", "user-1", "already revoked", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	err = store.Revoke("key-id")
	if err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}

	err = store.Revoke("key-id")
	if err != ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound for already revoked key, got %v", err)
	}
}

func TestAPIKeyStore_UpdateLastUsed(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	err := store.Create("key-id", "user-1", "used key", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	now := time.Now()
	err = store.UpdateLastUsed("key-id", now)
	if err != nil {
		t.Fatalf("failed to update last used: %v", err)
	}

	row, err := store.FindByKeyHash("key-id")
	if err != nil {
		t.Fatalf("failed to find key: %v", err)
	}

	if row.LastUsedAt == nil {
		t.Fatal("expected last_used_at to be set")
	}
}

func TestAPIKeyStore_UpdateLastUsedNotFound(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	err := store.UpdateLastUsed("nonexistent", time.Now())
	if err != ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

func TestAPIKeyStore_DeleteByUser(t *testing.T) {
	store := setupTestAPIKeyStore(t)

	err := store.Create("key-1", "user-1", "first", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	err = store.Create("key-2", "user-1", "second", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	err = store.Create("key-3", "user-2", "other", nil)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	err = store.DeleteByUser("user-1")
	if err != nil {
		t.Fatalf("failed to delete by user: %v", err)
	}

	keys, err := store.ListByUser("user-1")
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}

	keys2, err := store.ListByUser("user-2")
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	if len(keys2) != 1 {
		t.Errorf("expected 1 key for user-2, got %d", len(keys2))
	}
}
