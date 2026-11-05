// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres

import "time"

// What the tests of package postgres_test reach inside the store.
var (
	MigrationFiles = migrationFiles
)

// MigrationDir is the directory of MigrationFiles the migrations are in.
const MigrationDir = migrationDir

// SetClock makes the store stamp with now.
func SetClock(s *Store, now func() time.Time) { s.now = now }

// PoolSettings are the settings the store's pool was opened with.
func PoolSettings(s *Store) (maxConns int32, idle time.Duration) {
	cfg := s.pool.Config()
	return cfg.MaxConns, cfg.MaxConnIdleTime
}
