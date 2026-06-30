package auth

import (
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/perber/wiki/internal/core/shared"

	_ "modernc.org/sqlite"
)

type APIKeyRow struct {
	ID         string
	ShortID    string
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
	if err != nil {
		return err
	}

	// Migration: add short_id column if it doesn't exist
	_, err = s.db.Exec(`ALTER TABLE api_keys ADD COLUMN short_id TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		// Column already exists — ignore
	}

	// Backfill short IDs for existing rows
	rows, err := s.db.Query(`SELECT rowid FROM api_keys WHERE short_id = ''`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var rowid int64
		if err := rows.Scan(&rowid); err != nil {
			rows.Close()
			return err
		}
		shortID, err := shared.GenerateUniqueID()
		if err != nil {
			rows.Close()
			return err
		}
		_, err = s.db.Exec(`UPDATE api_keys SET short_id = ? WHERE rowid = ?`, shortID, rowid)
		if err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()

	// Unique index on short_id
	_, err = s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_short_id ON api_keys(short_id)`)
	if err != nil {
		return err
	}

	return nil
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

func (s *APIKeyStore) Create(keyID, shortID, userID, name string, expiresAt *time.Time) error {
	err := s.Connect()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO api_keys (id, short_id, user_id, name, expires_at)
		VALUES (?, ?, ?, ?, ?);
	`, keyID, shortID, userID, name, expiresAt)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrAPIKeyShortIDTaken
	}
	return err
}

func (s *APIKeyStore) FindByKeyHash(keyID string) (*APIKeyRow, error) {
	err := s.Connect()
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(`
		SELECT id, short_id, user_id, name, expires_at, created_at, last_used_at, revoked_at
		FROM api_keys
		WHERE id = ?;
	`, keyID)

	k := &APIKeyRow{}
	err = row.Scan(&k.ID, &k.ShortID, &k.UserID, &k.Name, &k.ExpiresAt, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrAPIKeyNotFound
		}
		return nil, err
	}
	return k, nil
}

func (s *APIKeyStore) FindByShortID(shortID string) (*APIKeyRow, error) {
	err := s.Connect()
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(`
		SELECT id, short_id, user_id, name, expires_at, created_at, last_used_at, revoked_at
		FROM api_keys
		WHERE short_id = ?;
	`, shortID)

	k := &APIKeyRow{}
	err = row.Scan(&k.ID, &k.ShortID, &k.UserID, &k.Name, &k.ExpiresAt, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
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
		SELECT id, short_id, user_id, name, expires_at, created_at, last_used_at, revoked_at
		FROM api_keys
		WHERE user_id = ? AND revoked_at IS NULL
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
		err = rows.Scan(&k.ID, &k.ShortID, &k.UserID, &k.Name, &k.ExpiresAt, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *APIKeyStore) CountByUser(userID string) (int, error) {
	err := s.Connect()
	if err != nil {
		return 0, err
	}
	row := s.db.QueryRow(`
		SELECT COUNT(*) FROM api_keys
		WHERE user_id = ? AND revoked_at IS NULL;
	`, userID)
	var count int
	err = row.Scan(&count)
	return count, err
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
