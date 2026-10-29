// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package postgres is the store in Postgres, for a server that keeps its
// state: the contract package memory serves, over one connection pool and
// the schema under migrations/. What memory does under its lock, this
// store does in one transaction.
//
// Times are kept to the microsecond, which is what a timestamptz holds:
// the store stamps with its clock cut to the microsecond, so a time it
// returns is the time it reads back.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strconv"
	"strings"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // the pgx5:// driver pgxmigrate selects by scheme
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"latere.ai/x/pkg/pgxmigrate"

	"latere.ai/x/sermo/internal/store"
)

// The pool's settings where the URL that opens it names none. The
// database a fleet of services shares has a small connection ceiling, so
// one replica holds few connections and hands an idle one back soon.
const (
	DefaultMaxConns        = 4
	DefaultMaxConnIdleTime = time.Minute
)

// migrationFiles is the schema, as golang-migrate files numbered from
// 000001 and applied in order at start. A released migration is never
// edited, because the databases that ran it already have.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

const migrationDir = "migrations"

// Options names the database.
type Options struct {
	// URL is a postgres:// URL on a direct endpoint or a session-mode
	// pooler. Migrations run over it whatever PoolURL says: a migration
	// holds a session-scoped lock across its statements, which a
	// transaction-mode pooler loses between transactions.
	URL string
	// PoolURL is a pooled endpoint for everything after the migrations.
	// Empty, the store serves over URL.
	PoolURL string
}

// Store is the store in Postgres.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ store.Store = (*Store)(nil)

// Open connects, refuses a schema this binary does not know, applies the
// migrations not yet applied, and returns the store. The pool takes the
// pool_* settings of the URL that opens it, and DefaultMaxConns and
// DefaultMaxConnIdleTime where it names none.
func Open(ctx context.Context, o Options) (*Store, error) {
	direct, err := migrationURL(o.URL)
	if err != nil {
		return nil, err
	}
	serving, which := o.URL, "database URL"
	if o.PoolURL != "" {
		serving, which = o.PoolURL, "pooled database URL"
	}
	cfg, err := poolConfig(serving, which)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: opening the pool: %w", err)
	}
	if err := prepare(ctx, pool, direct); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool, now: time.Now}, nil
}

// Ping reports whether the database answers, for a readiness probe.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: the database does not answer: %w", err)
	}
	return nil
}

// Close closes the pool, waiting for the connections in use to come
// back. Every call after it fails.
func (s *Store) Close() { s.pool.Close() }

// clock is the time the store stamps, cut to the microsecond a
// timestamptz holds. The driver would cut it on the way in as well; cut
// here, the time an append returns is the one the log reads back.
func (s *Store) clock() time.Time { return micro(s.now()) }

// micro cuts a time to the microsecond, in UTC.
func micro(t time.Time) time.Time { return t.Truncate(time.Microsecond).UTC() }

// parseURL reads a postgres:// URL. Its error never carries the URL,
// which may carry a password.
func parseURL(raw, which string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, fmt.Errorf("store: the %s is not a postgres:// URL", which)
	}
	return u, nil
}

// poolConfig is the pool the URL names, with the defaults of this
// package for the settings it does not name. pgxpool's own default
// connection count grows with the machine's CPUs, and one replica on a
// large machine would hold a share of the ceiling it was never given.
func poolConfig(raw, which string) (*pgxpool.Config, error) {
	u, err := parseURL(raw, which)
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(raw)
	if err != nil {
		// pgconn's error quotes the URL, password redacted; a query
		// parameter is not, so the error is this sentence alone.
		return nil, fmt.Errorf("store: the %s does not parse, or one of its pool_* settings does not", which)
	}
	q := u.Query()
	if !q.Has("pool_max_conns") {
		cfg.MaxConns = DefaultMaxConns
	}
	if !q.Has("pool_max_conn_idle_time") {
		cfg.MaxConnIdleTime = DefaultMaxConnIdleTime
	}
	return cfg, nil
}

// migrationURL is the direct URL under the scheme golang-migrate's pgx/v5
// driver registers, without the pool_* settings: that driver opens a
// single connection through pgx's stdlib, which sends a parameter it does
// not know to the server as a setting, and the server refuses to start a
// session with one it does not know either.
func migrationURL(raw string) (string, error) {
	u, err := parseURL(raw, "database URL")
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k := range q {
		if strings.HasPrefix(k, "pool_") {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	u.Scheme = "pgx5"
	return u.String(), nil
}

// prepare refuses a schema this binary does not know, and applies the
// migrations not yet applied.
func prepare(ctx context.Context, pool *pgxpool.Pool, direct string) error {
	highest, err := highestOf(migrationFiles, migrationDir)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := guard(ctx, pool, highest); err != nil {
		return err
	}
	if err := pgxmigrate.Up(direct, migrationFiles, migrationDir); err != nil {
		return fmt.Errorf("store: applying the schema: %w", err)
	}
	return nil
}

// guard reads schema_migrations before the migrator runs.
//
// A dirty flag means a migration failed halfway and the schema is at
// neither version; an operator repairs it, and Up over it would report
// the same failure with less to go on. A version above the newest this
// binary carries means an older binary met a newer schema: Up reports
// nothing to do, and every statement after it runs against tables this
// code does not know.
func guard(ctx context.Context, pool *pgxpool.Pool, highest uint64) error {
	var (
		version int64
		dirty   bool
	)
	err := pool.QueryRow(ctx, "select version, dirty from schema_migrations").Scan(&version, &dirty)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil // the migrator made its table and applied nothing
	case undefinedTable(err):
		return nil // a database with no schema yet
	case err != nil:
		return fmt.Errorf("store: reading the schema version: %w", err)
	case dirty:
		return fmt.Errorf("store: the schema is dirty at version %d: a migration failed halfway, and an operator repairs it before sermod starts", version)
	case version < 0 || uint64(version) > highest:
		return fmt.Errorf("store: the schema is at version %d and this binary carries %d: run the sermod that wrote the schema, or migrate down to %d", version, highest, highest)
	}
	return nil
}

// undefinedTable reports the one Postgres code that means a fresh
// database.
func undefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

// highestOf is the newest migration of a directory: the number its
// files start with.
func highestOf(files fs.FS, dir string) (uint64, error) {
	entries, err := fs.ReadDir(files, dir)
	if err != nil {
		return 0, fmt.Errorf("reading the migrations: %w", err)
	}
	var highest uint64
	for _, e := range entries {
		number, _, _ := strings.Cut(e.Name(), "_")
		n, err := strconv.ParseUint(number, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("the migration %q does not start with a number", e.Name())
		}
		highest = max(highest, n)
	}
	if highest == 0 {
		return 0, errors.New("no migration is embedded")
	}
	return highest, nil
}

// fail is an error of the store's: a sentinel of the contract as it is,
// anything else wrapped with what the store was doing.
func fail(doing string, err error) error {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrConflict) {
		return err
	}
	return fmt.Errorf("store: %s: %w", doing, err)
}

// inTx runs fn in one transaction, committed when fn returns nil and
// rolled back otherwise.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}

// querier is the pool, or a transaction of it.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// list runs a query and scans each row it returns.
func list[T any](ctx context.Context, q querier, sql string, args []any, scan func(pgx.CollectableRow) (T, error)) ([]T, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scan)
}

// orEmpty is a list that is never nil, for a column that is never null.
func orEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
