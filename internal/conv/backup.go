// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package conv

import (
	"context"
	"errors"
	"fmt"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/apierr"
	"latere.ai/x/sermo/internal/store"
)

// BackupRecord is one record to store: the id the person's devices
// derived and the record sealed under their backup key.
type BackupRecord struct {
	ID     string
	Sealed []byte
}

// MaxBackupIDBytes bounds a record's id, a keyed hash in base64.
const MaxBackupIDBytes = 64

// ownBackup asks the authorizer and checks that the conversation is one
// the caller is or was a person of. A person keeps the history of a
// conversation they left, and no one else's record is ever named.
func (s *Service) ownBackup(ctx context.Context, w Who, id string) error {
	c, err := s.conversation(ctx, id)
	if err != nil {
		return err
	}
	if err := s.ask(ctx, w, authorizer.ActionBackupRecovery, "", map[string]any{authorizer.FieldPerson: w.Person}); err != nil {
		return err
	}
	if c.Has(w.Person) {
		return nil
	}
	for _, m := range c.Members {
		if m.Person == w.Person {
			return nil
		}
	}
	return apierr.New(apierr.CodeForbidden, "the caller is not one of the conversation's people")
}

// PutBackup stores the caller's sealed records of a conversation and says
// how many were new: a record whose id is stored already is kept as it was.
func (s *Service) PutBackup(ctx context.Context, w Who, id string, records []BackupRecord) (int, error) {
	if len(records) == 0 {
		return 0, apierr.New(apierr.CodeInvalid, "no record to store")
	}
	if len(records) > MaxBackupBatch {
		return 0, apierr.New(apierr.CodeTooLarge, fmt.Sprintf("a call stores at most %d records", MaxBackupBatch))
	}
	in := make([]store.BackupRecord, 0, len(records))
	for _, r := range records {
		switch {
		case r.ID == "" || len(r.ID) > MaxBackupIDBytes:
			return 0, apierr.New(apierr.CodeInvalid, fmt.Sprintf("a record's id is 1 to %d characters", MaxBackupIDBytes))
		case len(r.Sealed) == 0:
			return 0, apierr.New(apierr.CodeInvalid, "a record is empty")
		case len(r.Sealed) > MaxBackupRecordBytes:
			return 0, apierr.New(apierr.CodeTooLarge, fmt.Sprintf("a record is at most %d bytes", MaxBackupRecordBytes))
		}
		in = append(in, store.BackupRecord{ID: r.ID, Sealed: r.Sealed})
	}
	if err := s.ownBackup(ctx, w, id); err != nil {
		return 0, err
	}
	n, err := s.store.PutBackupRecords(ctx, w.Person, id, in, s.backupLimit)
	if errors.Is(err, store.ErrFull) {
		return 0, apierr.New(apierr.CodeTooLarge, fmt.Sprintf("the person's backup holds at most %d bytes", s.backupLimit))
	}
	return n, err
}

// Backup lists the caller's records of a conversation by the cursor the
// store gave them, oldest after it or newest before it.
func (s *Service) Backup(ctx context.Context, w Who, id string, cursor int64, newest bool, limit int) ([]store.BackupRecord, error) {
	if err := s.ownBackup(ctx, w, id); err != nil {
		return nil, err
	}
	return s.store.BackupRecords(ctx, w.Person, id, cursor, newest, limit)
}
