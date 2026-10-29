// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/internal/store"
)

const (
	putDevice = `
insert into devices (person, id, kind, signature_key, encryption_key, voucher, voucher_key, vouch, possession)
values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
on conflict (person, id) do update set
    kind = excluded.kind, signature_key = excluded.signature_key, encryption_key = excluded.encryption_key,
    voucher = excluded.voucher, voucher_key = excluded.voucher_key, vouch = excluded.vouch,
    possession = excluded.possession`
	listDevices = `
select person, id, kind, signature_key, encryption_key, voucher, voucher_key, vouch, possession
from devices where person = $1 order by id`

	// addRevocation keeps the first of a person's revocations with one
	// signature, and its place in the order.
	addRevocation = `
insert into revocations (person, key, keep, signed_by, signature) values ($1, $2, $3, $4, $5)
on conflict (person, signature) do nothing`
	listRevocations = `
select person, key, keep, signed_by, signature from revocations where person = $1 order by ord`

	putRecovery = `
insert into recovery (person, wrapped) values ($1, $2)
on conflict (person) do update set wrapped = excluded.wrapped`
	getRecovery = `select wrapped from recovery where person = $1`

	putTransfer = `
insert into transfers (person, device, sealed) values ($1, $2, $3)
on conflict (person, device) do update set sealed = excluded.sealed`
	takeTransfer   = `delete from transfers where person = $1 and device = $2 returning sealed`
	deleteTransfer = `delete from transfers where person = $1 and device = $2`

	addKeyPackage = `
insert into key_packages (person, device, ref, data, last_resort, created) values ($1, $2, $3, $4, false, $5)`
	putLastResort = `
insert into key_packages (person, device, ref, data, last_resort, created) values ($1, $2, $3, $4, true, $5)
on conflict (person, device) where last_resort do update set
    ref = excluded.ref, data = excluded.data, created = excluded.created`
	countKeyPackages = `
select count(*) filter (where not last_resort), coalesce(bool_or(last_resort), false)
from key_packages where person = $1 and device = $2`
	// claimOneTime deletes the oldest one-time package no other
	// transaction holds. Skipping a locked one rather than waiting on it,
	// claims of one device's packages run side by side instead of in a
	// queue behind the oldest.
	claimOneTime = `
delete from key_packages where ord = (
    select ord from key_packages where person = $1 and device = $2 and not last_resort
    order by ord limit 1 for update skip locked)
returning ref, person, device, data, last_resort, created`
	lastResort = `
select ref, person, device, data, last_resort, created
from key_packages where person = $1 and device = $2 and last_resort`
	deleteKeyPackages = `delete from key_packages where person = $1 and device = $2`
)

// PutDevice adds or replaces a record.
func (s *Store) PutDevice(ctx context.Context, r messaging.DeviceRecord) error {
	if _, err := s.pool.Exec(ctx, putDevice, r.Person, r.ID, r.Kind, r.SignatureKey, r.EncryptionKey,
		r.Voucher, r.VoucherKey, r.Vouch, r.Possession); err != nil {
		return fail("putting a device record", err)
	}
	return nil
}

// Devices lists a person's records by id.
func (s *Store) Devices(ctx context.Context, person string) ([]messaging.DeviceRecord, error) {
	out, err := list(ctx, s, listDevices, []any{person}, func(row pgx.CollectableRow) (messaging.DeviceRecord, error) {
		var r messaging.DeviceRecord
		err := row.Scan(&r.Person, &r.ID, &r.Kind, &r.SignatureKey, &r.EncryptionKey, &r.Voucher, &r.VoucherKey, &r.Vouch, &r.Possession)
		return r, err
	})
	if err != nil {
		return nil, fail("listing device records", err)
	}
	return out, nil
}

// AddRevocation keeps a revocation once and, when it names a device,
// deletes that device's key packages and transfer with it.
func (s *Store) AddRevocation(ctx context.Context, v messaging.Revocation, device string) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		b.Queue(addRevocation, v.Person, v.Key, v.Keep, v.By, orNone(v.Signature))
		if device != "" {
			b.Queue(deleteKeyPackages, v.Person, device)
			b.Queue(deleteTransfer, v.Person, device)
		}
		return tx.SendBatch(ctx, b).Close()
	})
	if err != nil {
		return fail("adding a revocation", err)
	}
	return nil
}

// Revocations lists a person's revocations in the order they came.
func (s *Store) Revocations(ctx context.Context, person string) ([]messaging.Revocation, error) {
	out, err := list(ctx, s, listRevocations, []any{person}, func(row pgx.CollectableRow) (messaging.Revocation, error) {
		var v messaging.Revocation
		err := row.Scan(&v.Person, &v.Key, &v.Keep, &v.By, &v.Signature)
		return v, err
	})
	if err != nil {
		return nil, fail("listing revocations", err)
	}
	return out, nil
}

// PutRecovery stores the wrapped backup key.
func (s *Store) PutRecovery(ctx context.Context, person string, wrapped []byte) error {
	if _, err := s.pool.Exec(ctx, putRecovery, person, wrapped); err != nil {
		return fail("putting a recovery key", err)
	}
	return nil
}

// Recovery is a person's wrapped backup key.
func (s *Store) Recovery(ctx context.Context, person string) ([]byte, error) {
	var wrapped []byte
	if err := s.pool.QueryRow(ctx, getRecovery, person).Scan(&wrapped); err != nil {
		return nil, fail("reading a recovery key", notFound(err))
	}
	return wrapped, nil
}

// PutTransfer leaves a sealed backup key for a device.
func (s *Store) PutTransfer(ctx context.Context, person, device string, sealed []byte) error {
	if _, err := s.pool.Exec(ctx, putTransfer, person, device, sealed); err != nil {
		return fail("putting a transfer", err)
	}
	return nil
}

// TakeTransfer returns and deletes what was left for a device, in one
// statement, so of two takes one finds it.
func (s *Store) TakeTransfer(ctx context.Context, person, device string) ([]byte, error) {
	var sealed []byte
	if err := s.pool.QueryRow(ctx, takeTransfer, person, device).Scan(&sealed); err != nil {
		return nil, fail("taking a transfer", notFound(err))
	}
	return sealed, nil
}

// AddKeyPackages adds key packages, all or none. A package with no time
// is stamped with the store's clock.
func (s *Store) AddKeyPackages(ctx context.Context, kps []store.KeyPackage) error {
	if len(kps) == 0 {
		return nil
	}
	now := s.clock()
	b := &pgx.Batch{}
	for _, kp := range kps {
		created := kp.Created
		if created.IsZero() {
			created = now
		}
		stmt := addKeyPackage
		if kp.LastResort {
			stmt = putLastResort
		}
		b.Queue(stmt, kp.Person, kp.Device, kp.Ref, kp.Data, created)
	}
	if err := s.inTx(ctx, func(tx pgx.Tx) error { return tx.SendBatch(ctx, b).Close() }); err != nil {
		return fail("adding key packages", err)
	}
	return nil
}

// CountKeyPackages counts a device's key packages.
func (s *Store) CountKeyPackages(ctx context.Context, person, device string) (int, bool, error) {
	var (
		n          int
		lastResort bool
	)
	if err := s.pool.QueryRow(ctx, countKeyPackages, person, device).Scan(&n, &lastResort); err != nil {
		return 0, false, fail("counting key packages", err)
	}
	return n, lastResort, nil
}

// ClaimKeyPackage hands out a device's oldest one-time package, deleting
// it, or its last resort, keeping it.
func (s *Store) ClaimKeyPackage(ctx context.Context, person, device string) (store.KeyPackage, error) {
	kp, err := scanKeyPackage(s.pool.QueryRow(ctx, claimOneTime, person, device))
	if errors.Is(err, pgx.ErrNoRows) {
		kp, err = scanKeyPackage(s.pool.QueryRow(ctx, lastResort, person, device))
	}
	if err != nil {
		return store.KeyPackage{}, fail("claiming a key package", notFound(err))
	}
	return kp, nil
}

func scanKeyPackage(row pgx.Row) (store.KeyPackage, error) {
	var kp store.KeyPackage
	err := row.Scan(&kp.Ref, &kp.Person, &kp.Device, &kp.Data, &kp.LastResort, &kp.Created)
	return kp, err
}

// notFound is ErrNotFound for a row that is not there.
func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// orNone is a byte string that is never nil, for a column that is never
// null: a revocation is kept once by its signature, and a missing one is
// the empty one.
func orNone(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
