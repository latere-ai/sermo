// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"latere.ai/x/sermo/internal/store"
)

const (
	// lockBackup holds a person's backup until the transaction ends, so
	// two writes cannot both pass the limit.
	lockBackup = `select pg_advisory_xact_lock(hashtextextended('sermo.backup:' || $1, 0))`

	putBackupRecord = `
insert into backup_records (person, conversation, id, sealed, created) values ($1, $2, $3, $4, $5)
on conflict (person, conversation, id) do nothing`
	addBackupUsage = `
insert into backup_usage (person, bytes) values ($1, $2)
on conflict (person) do update set bytes = backup_usage.bytes + excluded.bytes
returning bytes`

	oldestBackupRecords = `
select id, sealed, seq, created from backup_records
where person = $1 and conversation = $2 and seq > $3 order by seq limit $4`
	newestBackupRecords = `
select id, sealed, seq, created from backup_records
where person = $1 and conversation = $2 and ($3 = 0 or seq < $3) order by seq desc limit $4`
)

// PutBackupRecords stores backup records, keeping the first of an id,
// and the person's bytes with them, in one transaction.
func (s *Store) PutBackupRecords(ctx context.Context, person, conversation string, records []store.BackupRecord, limit int64) (int, error) {
	added := 0
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, lockBackup, person); err != nil {
			return err
		}
		var size int64
		now := s.clock()
		for _, r := range records {
			tag, err := tx.Exec(ctx, putBackupRecord, person, conversation, r.ID, r.Sealed, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				added++
				size += int64(len(r.Sealed))
			}
		}
		if added == 0 {
			return nil
		}
		var total int64
		if err := tx.QueryRow(ctx, addBackupUsage, person, size).Scan(&total); err != nil {
			return err
		}
		if total > limit {
			// Returning the error rolls the records back with the count.
			return store.ErrFull
		}
		return nil
	})
	if err != nil {
		return 0, fail("putting backup records", err)
	}
	return added, nil
}

// BackupRecords lists a person's records of a conversation by seq.
func (s *Store) BackupRecords(ctx context.Context, person, conversation string, cursor int64, newest bool, limit int) ([]store.BackupRecord, error) {
	if limit < 1 {
		return nil, nil
	}
	q := oldestBackupRecords
	if newest {
		q = newestBackupRecords
	}
	out, err := list(ctx, s.pool, q, []any{person, conversation, cursor, limit}, func(row pgx.CollectableRow) (store.BackupRecord, error) {
		var r store.BackupRecord
		err := row.Scan(&r.ID, &r.Sealed, &r.Seq, &r.Created)
		return r, err
	})
	if err != nil {
		return nil, fail("listing backup records", err)
	}
	return out, nil
}
