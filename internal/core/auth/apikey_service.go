package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	UserID     string     `json:"userID"`
	Key        string     `json:"key,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

type APIKeyService struct {
	store *APIKeyStore
	user  *UserService
}

func NewAPIKeyService(store *APIKeyStore, user *UserService) *APIKeyService {
	return &APIKeyService{
		store: store,
		user:  user,
	}
}

func generateAPIKey() (string, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate api key: %w", err)
	}
	return fmt.Sprintf("lw_%x", b), nil
}

func (s *APIKeyService) Create(userID, name string, expiresAt *time.Time) (*APIKey, error) {
	user, err := s.user.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	key, err := generateAPIKey()
	if err != nil {
		return nil, err
	}

	hashed := hashAPIKey(key)

	if err := s.store.Create(hashed, userID, name, expiresAt); err != nil {
		return nil, err
	}

	return &APIKey{
		ID:        hashed,
		Name:      name,
		UserID:    user.ID,
		Key:       key,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}, nil
}

func (s *APIKeyService) Authenticate(key string) (*User, error) {
	hashed := hashAPIKey(key)

	row, err := s.store.FindByKeyHash(hashed)
	if err != nil {
		if err == ErrAPIKeyNotFound {
			return nil, ErrAPIKeyNotFound
		}
		return nil, err
	}

	if row.RevokedAt != nil {
		return nil, ErrAPIKeyRevoked
	}

	if row.ExpiresAt != nil && time.Now().After(*row.ExpiresAt) {
		return nil, ErrAPIKeyExpired
	}

	now := time.Now()
	if err := s.store.UpdateLastUsed(hashed, now); err != nil {
		// non-critical, continue
	}

	user, err := s.user.GetUserByID(row.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found for api key: %w", err)
	}

	return user, nil
}

func (s *APIKeyService) List(userID string) ([]APIKey, error) {
	rows, err := s.store.ListByUser(userID)
	if err != nil {
		return nil, err
	}

	keys := make([]APIKey, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, APIKey{
			ID:         r.ID,
			Name:       r.Name,
			UserID:     r.UserID,
			ExpiresAt:  r.ExpiresAt,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
		})
	}
	return keys, nil
}

func (s *APIKeyService) Revoke(keyID, userID string) error {
	row, err := s.store.FindByKeyHash(keyID)
	if err != nil {
		return err
	}
	if row.UserID != userID {
		return ErrAPIKeyNotFound
	}
	return s.store.Revoke(keyID)
}

func (s *APIKeyService) DeleteByUser(userID string) error {
	return s.store.DeleteByUser(userID)
}

func (s *APIKeyService) Close() error {
	return s.store.Close()
}

func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
