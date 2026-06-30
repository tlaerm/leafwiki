package auth

import (
	"database/sql"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type APIKeyRow struct {
	ID         string
	UserID     string
	Name       string
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

type APIKeyStore struct {
	mu         sync.Mutex
	storageDir string
	filename   string
	db         *sql.DB
}

func NewAPIKeyStore(storageDir string) (*APIKeyStore, error) {
	s := &APIKeyStore{
		storageDir: storageDir,
		filename:   "api_keys.db",
	}

	err := s.Connect()
	if err != nil {
		return nil, err
	}

	return s, s.ensureSchema()
}

func (s *APIKeyStore) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return nil
	}
	db, err := sql.Open("sqlite", databasePath(s.storageDir, s.filename))
	if err != nil {
		return err
	}
	s.db = db
	return nil
}

func (s *APIKeyStore) ensureSchema() error {
	err := s.Connect()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			expires_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at TIMESTAMP,
			revoked_at TIMESTAMP
		);
	`)
	return err
}

func (s *APIKeyStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		err := s.db.Close()
		if err != nil {
			return err
		}
		s.db = nil
	}
	return nil
}

func (s *APIKeyStore) Create(keyID, userID, name string, expiresAt *time.Time) error {
	err := s.Connect()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO api_keys (id, user_id, name, expires_at)
		VALUES (?, ?, ?, ?);
	`, keyID, userID, name, expiresAt)
	return err
}

func (s *APIKeyStore) FindByKeyHash(keyID string) (*APIKeyRow, error) {
	err := s.Connect()
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(`
		SELECT id, user_id, name, expires_at, created_at, last_used_at, revoked_at
		FROM api_keys
		WHERE id = ?;
	`, keyID)

	k := &APIKeyRow{}
	err = row.Scan(&k.ID, &k.UserID, &k.Name, &k.ExpiresAt, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrAPIKeyNotFound
		}
		return nil, err
	}
	return k, nil
}

func (s *APIKeyStore) ListByUser(userID string) ([]APIKeyRow, error) {
	err := s.Connect()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`
		SELECT id, user_id, name, expires_at, created_at, last_used_at, revoked_at
		FROM api_keys
		WHERE user_id = ?
		ORDER BY created_at DESC;
	`, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Default().Error("could not close rows", "error", err)
		}
	}()

	var keys []APIKeyRow
	for rows.Next() {
		k := APIKeyRow{}
		err = rows.Scan(&k.ID, &k.UserID, &k.Name, &k.ExpiresAt, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *APIKeyStore) Revoke(keyID string) error {
	err := s.Connect()
	if err != nil {
		return err
	}
	result, err := s.db.Exec(`
		UPDATE api_keys
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE id = ? AND revoked_at IS NULL;
	`, keyID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

func (s *APIKeyStore) UpdateLastUsed(keyID string, now time.Time) error {
	err := s.Connect()
	if err != nil {
		return err
	}
	result, err := s.db.Exec(`
		UPDATE api_keys
		SET last_used_at = ?
		WHERE id = ?;
	`, now, keyID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

func (s *APIKeyStore) DeleteByUser(userID string) error {
	err := s.Connect()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		DELETE FROM api_keys
		WHERE user_id = ?;
	`, userID)
	return err
}
