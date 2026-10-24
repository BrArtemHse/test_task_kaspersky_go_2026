// Package store persists threats in a local SQLite database.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
	"threat-exchange/internal/threat"
)

// Store owns a database pool. Close it after HTTP requests have drained.
type Store struct{ db *sql.DB }

//go:embed migrations/001_threats.sql
var schema string

// Open opens a file-backed WAL database and applies the initial migration atomically.
func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	if filepath.VolumeName(abs) != "" {
		u.Path = "/" + u.Path
	}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	switch version {
	case 0:
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return fmt.Errorf("apply migration: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 1"); err != nil {
			return fmt.Errorf("write schema version: %w", err)
		}
	case 1:
	default:
		return fmt.Errorf("unsupported database schema version %d", version)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}

// Close releases database resources.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks that a database connection is available.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

const columns = "md5, name, description, category, severity, first_seen, created_at, updated_at"

// Get returns one record or threat.ErrNotFound.
func (s *Store) Get(ctx context.Context, md5 string) (threat.Threat, error) {
	return scan(s.db.QueryRowContext(ctx, "SELECT "+columns+" FROM threats WHERE md5 = ?", md5))
}

// Create inserts atomically; the primary key resolves concurrent duplicate inserts.
func (s *Store) Create(ctx context.Context, item threat.Threat) (threat.Threat, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	row := s.db.QueryRowContext(ctx, "INSERT INTO threats ("+columns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING "+columns,
		item.MD5, item.Name, item.Description, item.Category, item.Severity, firstSeenValue(item.FirstSeen), now, now)
	result, err := scan(row)
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code() == 1555 {
		return threat.Threat{}, threat.ErrConflict
	}
	return result, err
}

// Update replaces mutable attributes, preserving identity and creation time.
func (s *Store) Update(ctx context.Context, item threat.Threat) (threat.Threat, error) {
	return scan(s.db.QueryRowContext(ctx, "UPDATE threats SET name = ?, description = ?, category = ?, severity = ?, first_seen = ?, updated_at = ? WHERE md5 = ? RETURNING "+columns,
		item.Name, item.Description, item.Category, item.Severity, firstSeenValue(item.FirstSeen), time.Now().UTC().Format(time.RFC3339Nano), item.MD5))
}

func firstSeenValue(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func scan(row *sql.Row) (threat.Threat, error) {
	var item threat.Threat
	var first sql.NullString
	var created, updated string
	if err := row.Scan(&item.MD5, &item.Name, &item.Description, &item.Category, &item.Severity, &first, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return threat.Threat{}, threat.ErrNotFound
		}
		return threat.Threat{}, fmt.Errorf("read threat: %w", err)
	}
	var err error
	if item.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return threat.Threat{}, fmt.Errorf("parse created_at: %w", err)
	}
	if item.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated); err != nil {
		return threat.Threat{}, fmt.Errorf("parse updated_at: %w", err)
	}
	if first.Valid {
		value, err := time.Parse(time.RFC3339Nano, first.String)
		if err != nil {
			return threat.Threat{}, fmt.Errorf("parse first_seen: %w", err)
		}
		item.FirstSeen = &value
	}
	return item, nil
}
