// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"

	"latere.ai/x/pkg/pgxmigrate"
	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/internal/store"
	"latere.ai/x/sermo/internal/store/postgres"
	"latere.ai/x/sermo/internal/store/storetest"
)

// TestContract runs the store contract against Postgres.
func TestContract(t *testing.T) {
	admin := server(t)
	storetest.Run(t, func(t *testing.T) store.Store {
		return open(t, postgres.Options{URL: database(t, admin)})
	})
}

// TestContractInExecMode runs the contract with the serving pool in the
// query mode a transaction pooler's URL selects. In it the server
// describes no parameter, so the driver encodes each value from its Go
// type alone and sends it as text, which a statement that only ever ran
// described can fail.
func TestContractInExecMode(t *testing.T) {
	admin := server(t)
	storetest.Run(t, func(t *testing.T) store.Store {
		dsn := database(t, admin)
		return open(t, postgres.Options{URL: dsn, PoolURL: execMode(t, dsn)})
	})
}

// TestOpenTakesThePoolSettingsOfItsURL: the pool keeps the pool_* settings
// of the URL that opens it and takes the small defaults for the rest, and
// the migrations still run over the direct URL, whose driver would send a
// pool_* setting to the server as one of its own and be refused.
func TestOpenTakesThePoolSettingsOfItsURL(t *testing.T) {
	admin := server(t)
	dsn := database(t, admin)
	for _, tc := range []struct {
		name     string
		o        postgres.Options
		maxConns int32
		idle     time.Duration
	}{
		{"the defaults", postgres.Options{URL: dsn}, postgres.DefaultMaxConns, postgres.DefaultMaxConnIdleTime},
		{"the direct URL's", postgres.Options{URL: withQuery(t, withQuery(t, dsn, "pool_max_conns", "2"), "pool_max_conn_idle_time", "5m")}, 2, 5 * time.Minute},
		{"the pooled URL's over the direct one's", postgres.Options{
			URL: withQuery(t, dsn, "pool_max_conns", "2"), PoolURL: withQuery(t, execMode(t, dsn), "pool_max_conns", "3"),
		}, 3, postgres.DefaultMaxConnIdleTime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := open(t, tc.o)
			maxConns, idle := postgres.PoolSettings(s)
			if maxConns != tc.maxConns || idle != tc.idle {
				t.Errorf("the pool holds %d connections idle for %v, want %d and %v", maxConns, idle, tc.maxConns, tc.idle)
			}
			if err := s.Ping(t.Context()); err != nil {
				t.Errorf("Ping: %v", err)
			}
		})
	}
}

// TestOpenRefusesWhatIsNotAPostgresURL: a URL the store cannot open is a
// start-up failure, and the failure carries no password.
func TestOpenRefusesWhatIsNotAPostgresURL(t *testing.T) {
	const password = "s3cret-password"
	good := "postgres://sermo:" + password + "@127.0.0.1:1/sermo"
	for _, tc := range []struct {
		name string
		o    postgres.Options
		want string
	}{
		{"no URL", postgres.Options{}, "database URL is not a postgres:// URL"},
		{"another scheme", postgres.Options{URL: "mysql://sermo:" + password + "@127.0.0.1/sermo"}, "database URL is not a postgres:// URL"},
		{"no URL at all", postgres.Options{URL: "postgres://sermo:" + password + "@[::1"}, "database URL is not a postgres:// URL"},
		{"a pooled URL of another scheme", postgres.Options{URL: good, PoolURL: "http://sermo:" + password + "@127.0.0.1/"}, "pooled database URL is not a postgres:// URL"},
		{"a pool setting that is not a number", postgres.Options{URL: good + "?pool_max_conns=many"}, "pool_* settings"},
		{"a server that does not answer", postgres.Options{URL: good + "?connect_timeout=2"}, "the database does not answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := postgres.Open(t.Context(), tc.o)
			if err == nil {
				s.Close()
				t.Fatal("the store opened")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the failure %q does not say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), password) {
				t.Errorf("the failure carries the password: %q", err)
			}
		})
	}
}

// TestHighestIsWhatIsEmbedded: the number the store guards against is
// read from the files this binary carries, and every migration has the
// down half golang-migrate reads on the way back.
func TestHighestIsWhatIsEmbedded(t *testing.T) {
	highest, err := pgxmigrate.HighestOf(postgres.MigrationFiles, postgres.MigrationDir)
	if err != nil {
		t.Fatal(err)
	}
	ups, err := fs.Glob(postgres.MigrationFiles, postgres.MigrationDir+"/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if highest != uint(len(ups)) {
		t.Errorf("the highest migration is %d over %d up file(s): a number is missing or taken twice", highest, len(ups))
	}
	for _, up := range ups {
		down := strings.TrimSuffix(up, ".up.sql") + ".down.sql"
		if _, err := fs.Stat(postgres.MigrationFiles, down); err != nil {
			t.Errorf("%s has no down migration: %v", up, err)
		}
	}
}

// TestSchemaGuards: a schema the binary does not know is a start-up
// failure, not a server that runs statements against tables it cannot
// see.
func TestSchemaGuards(t *testing.T) {
	admin := server(t)
	for _, tc := range []struct {
		name, statement, want string
	}{
		{"ahead of the binary", `update schema_migrations set version = 9999, dirty = false`, "9999"},
		{"dirty", `update schema_migrations set dirty = true`, "dirty at version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn := database(t, admin)
			// One clean start writes schema_migrations, which the case moves.
			open(t, postgres.Options{URL: dsn}).Close()
			execute(t, dsn, tc.statement)
			s, err := postgres.Open(t.Context(), postgres.Options{URL: dsn})
			if err == nil {
				s.Close()
				t.Fatal("the store started against a schema it does not know")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the failure does not name %q: %v", tc.want, err)
			}
		})
	}
}

// TestAMigrationThatFailsIsAFailedStart: a database holding a table the
// first migration makes is refused at start, and the next start reports
// the schema dirty rather than running over it.
func TestAMigrationThatFailsIsAFailedStart(t *testing.T) {
	dsn := database(t, server(t))
	execute(t, dsn, `create table devices (id text)`)
	s, err := postgres.Open(t.Context(), postgres.Options{URL: dsn})
	if err == nil {
		s.Close()
		t.Fatal("the store started over a table of another schema")
	}
	if !strings.Contains(err.Error(), "applying the schema") {
		t.Errorf("the failure does not say the schema did not apply: %v", err)
	}
	if s, err := postgres.Open(t.Context(), postgres.Options{URL: dsn}); err == nil || !strings.Contains(err.Error(), "dirty") {
		if s != nil {
			s.Close()
		}
		t.Errorf("the start after the failed one = %v, want the schema dirty", err)
	}
}

// TestTheMigrationsGoDownAndUpAgain: every migration's down half undoes
// its up half, so a schema migrated down to nothing holds no table of the
// store's, and migrated up again serves.
func TestTheMigrationsGoDownAndUpAgain(t *testing.T) {
	dsn := database(t, server(t))
	open(t, postgres.Options{URL: dsn}).Close()
	tables := []string{"devices", "revocations", "recovery", "transfers", "key_packages", "conversations", "messages", "welcomes"}
	migrator := func() *migrate.Migrate {
		src, err := iofs.New(postgres.MigrationFiles, postgres.MigrationDir)
		if err != nil {
			t.Fatal(err)
		}
		u, err := pgxmigrate.DriverURL(dsn)
		if err != nil {
			t.Fatal(err)
		}
		m, err := migrate.NewWithSourceInstance("iofs", src, u)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if srcErr, dbErr := m.Close(); srcErr != nil || dbErr != nil {
				t.Errorf("closing the migrator: %v, %v", srcErr, dbErr)
			}
		})
		return m
	}
	if err := migrator().Down(); err != nil {
		t.Fatalf("migrating down: %v", err)
	}
	conn, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			t.Errorf("closing the connection: %v", err)
		}
	}()
	for _, table := range tables {
		var found *string
		if err := conn.QueryRow(t.Context(), `select to_regclass($1)::text`, "public."+table).Scan(&found); err != nil {
			t.Fatal(err)
		}
		if found != nil {
			t.Errorf("migrated down, the schema still holds %s", *found)
		}
	}
	s := open(t, postgres.Options{URL: dsn})
	if err := s.CreateConversation(t.Context(), store.Conversation{ID: "c01", People: []string{"person-a"}}); err != nil {
		t.Errorf("CreateConversation after migrating up again: %v", err)
	}
}

// TestReplicasStartTogether: two replicas starting at once on an empty
// database both start, one of them applying the schema while the other
// waits on the migrator's lock.
func TestReplicasStartTogether(t *testing.T) {
	dsn := database(t, server(t))
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() {
			s, err := postgres.Open(t.Context(), postgres.Options{URL: dsn})
			if err == nil {
				s.Close()
			}
			errs[i] = err
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d did not start: %v", i, err)
		}
	}
}

// TestTwoReplicasRace: the races of the contract between two stores on
// one database, as two replicas of sermod are: a lost append is a
// conflict and a key package goes to one claim, because the database
// decides and not either process.
func TestTwoReplicasRace(t *testing.T) {
	dsn := database(t, server(t))
	replicas := []*postgres.Store{open(t, postgres.Options{URL: dsn}), open(t, postgres.Options{URL: dsn})}
	ctx := t.Context()
	c := store.Conversation{ID: "c01", People: []string{"person-a"}, View: []byte("fake view at epoch 0")}
	if err := replicas[0].CreateConversation(ctx, c); err != nil {
		t.Fatal(err)
	}
	const racers = 8
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			state := c
			state.View = fmt.Appendf(nil, "fake view of proposal %d", i)
			_, errs[i] = replicas[i%2].Append(ctx, "c01", 0, store.Append{
				Message: store.Message{Kind: store.KindProposal, Data: fmt.Appendf(nil, "fake proposal %d", i)}, State: &state,
			})
		})
	}
	wg.Wait()
	won, conflicts := -1, 0
	for i, err := range errs {
		switch {
		case err == nil:
			won = i
		case errors.Is(err, store.ErrConflict):
			conflicts++
		}
	}
	if won < 0 || conflicts != racers-1 {
		t.Fatalf("%d of %d proposals across two replicas conflicted, want all but one: %v", conflicts, racers, errs)
	}
	for i, s := range replicas {
		got, err := s.Conversation(ctx, "c01")
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Appendf(nil, "fake view of proposal %d", won); got.Version != 1 || got.Seq != 1 || !bytes.Equal(got.View, want) {
			t.Errorf("replica %d reads version %d, seq %d and view %q, want 1, 1 and %q", i, got.Version, got.Seq, got.View, want)
		}
	}

	var kps []store.KeyPackage
	for i := range racers {
		kps = append(kps, store.KeyPackage{Ref: fmt.Sprintf("%02x", i), Person: "person-a", Device: "dev-a", Data: fmt.Appendf(nil, "fake key package %d", i)})
	}
	if err := replicas[1].AddKeyPackages(ctx, kps); err != nil {
		t.Fatal(err)
	}
	refs := make([]string, 2*racers)
	claimErrs := make([]error, 2*racers)
	for i := range 2 * racers {
		wg.Go(func() {
			kp, err := replicas[i%2].ClaimKeyPackage(ctx, "person-a", "dev-a")
			refs[i], claimErrs[i] = kp.Ref, err
		})
	}
	wg.Wait()
	handed := map[string]bool{}
	missed := 0
	for i, err := range claimErrs {
		switch {
		case err == nil:
			handed[refs[i]] = true
		case errors.Is(err, store.ErrNotFound):
			missed++
		default:
			t.Errorf("a claim failed: %v", err)
		}
	}
	if len(handed) != racers || missed != racers {
		t.Errorf("claims across two replicas handed out %d distinct packages and %d found none, want %d and %d", len(handed), missed, racers, racers)
	}
}

// TestAClaimDoesNotWaitOnAHeldPackage: while another transaction holds a
// device's oldest key package, a claim hands out the next one at once
// rather than waiting for that transaction to end, and the held one is
// handed out once it is let go.
func TestAClaimDoesNotWaitOnAHeldPackage(t *testing.T) {
	dsn := database(t, server(t))
	s := open(t, postgres.Options{URL: dsn})
	ctx := t.Context()
	if err := s.AddKeyPackages(ctx, []store.KeyPackage{
		{Ref: "01", Person: "person-a", Device: "dev-a", Data: []byte("fake key package 1")},
		{Ref: "02", Person: "person-a", Device: "dev-a", Data: []byte("fake key package 2")},
	}); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			t.Errorf("closing the connection: %v", err)
		}
	}()
	holder, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var held string
	if err := holder.QueryRow(ctx, `select ref from key_packages order by ord limit 1 for update`).Scan(&held); err != nil {
		t.Fatal(err)
	}
	soon, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	kp, err := s.ClaimKeyPackage(soon, "person-a", "dev-a")
	if err != nil || kp.Ref != "02" {
		t.Errorf("a claim while %s is held = %q, %v; want 02 at once", held, kp.Ref, err)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if kp, err := s.ClaimKeyPackage(ctx, "person-a", "dev-a"); err != nil || kp.Ref != "01" {
		t.Errorf("a claim once %s is let go = %q, %v; want 01", held, kp.Ref, err)
	}
}

// TestACreateRaceHasOneWinner: of creates of one id at once, one stores
// the conversation and the rest find the id taken.
func TestACreateRaceHasOneWinner(t *testing.T) {
	s := open(t, postgres.Options{URL: database(t, server(t))})
	const racers = 8
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			errs[i] = s.CreateConversation(t.Context(), store.Conversation{ID: "c01", People: []string{fmt.Sprintf("person-%d", i)}})
		})
	}
	wg.Wait()
	created, taken := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, store.ErrExists):
			taken++
		}
	}
	if created != 1 || taken != racers-1 {
		t.Errorf("%d creates stored the conversation and %d found it taken, want 1 and %d: %v", created, taken, racers-1, errs)
	}
}

// TestAWriteThatFailsChangesNothing: a write the database refuses partway
// leaves nothing of itself, for each write of several statements. The
// statement refused is the last one: a text value with a NUL byte, which
// Postgres does not store.
func TestAWriteThatFailsChangesNothing(t *testing.T) {
	s := open(t, postgres.Options{URL: database(t, server(t))})
	ctx := t.Context()
	c := store.Conversation{ID: "c01", People: []string{"person-a"}, Members: []store.Member{{Person: "person-a", Device: "dev-a"}}}
	if err := s.CreateConversation(ctx, c); err != nil {
		t.Fatal(err)
	}
	state := c
	state.Epoch, state.People = 1, []string{"person-a", "person-b"}
	_, err := s.Append(ctx, "c01", 0, store.Append{
		Message: store.Message{Kind: store.KindCommit, Person: "person-a", Device: "dev-a", Data: []byte("fake commit")},
		State:   &state,
		Welcomes: []store.Welcome{
			{ID: "w-1", Person: "person-b", Device: "dev-b", Data: []byte("fake welcome")},
			{ID: "w-\x00", Person: "person-b", Device: "dev-c", Data: []byte("fake welcome")},
		},
	})
	refused(t, err, "Append whose second welcome the database refuses")
	got, err := s.Conversation(ctx, "c01")
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 0 || got.Version != 0 || got.Epoch != 0 || len(got.People) != 1 {
		t.Errorf("a refused append left the conversation at seq %d, version %d, epoch %d, people %v", got.Seq, got.Version, got.Epoch, got.People)
	}
	if msgs, err := s.Messages(ctx, "c01", 0, 10); err != nil || len(msgs) != 0 {
		t.Errorf("a refused append left messages %+v, %v", msgs, err)
	}
	if ws, err := s.Welcomes(ctx, "person-b", "dev-b"); err != nil || len(ws) != 0 {
		t.Errorf("a refused append left welcomes %+v, %v", ws, err)
	}

	err = s.AddKeyPackages(ctx, []store.KeyPackage{
		{Ref: "01", Person: "person-a", Device: "dev-a", Data: []byte("fake key package")},
		{Ref: "0\x00", Person: "person-a", Device: "dev-a", Data: []byte("fake key package"), LastResort: true},
	})
	refused(t, err, "AddKeyPackages whose second package the database refuses")
	if n, last, err := s.CountKeyPackages(ctx, "person-a", "dev-a"); err != nil || n != 0 || last {
		t.Errorf("a refused publish left %d packages and last resort %v: %v", n, last, err)
	}

	if err := s.PutTransfer(ctx, "person-a", "dev-a", []byte("fake sealed backup key")); err != nil {
		t.Fatal(err)
	}
	v := messaging.Revocation{Person: "person-a", By: "dev-a", Signature: []byte("fake revocation signature")}
	refused(t, s.AddRevocation(ctx, v, "dev-\x00", nil), "AddRevocation whose device the database refuses")
	if vs, err := s.Revocations(ctx, "person-a"); err != nil || len(vs) != 0 {
		t.Errorf("a refused revocation was kept: %+v, %v", vs, err)
	}
	if _, err := s.TakeTransfer(ctx, "person-a", "dev-a"); err != nil {
		t.Errorf("a refused revocation took the transfer of another device: %v", err)
	}
}

// TestARevocationWithNoSignatureIsKeptOnce: a revocation is kept once by
// its signature, and one with none is kept once too, as the store in
// memory keeps it, rather than refused by a column that holds no null.
func TestARevocationWithNoSignatureIsKeptOnce(t *testing.T) {
	s := open(t, postgres.Options{URL: database(t, server(t))})
	ctx := t.Context()
	v := messaging.Revocation{Person: "person-a", By: "dev-a", Key: []byte("fake signature key")}
	for range 2 {
		if err := s.AddRevocation(ctx, v, "", nil); err != nil {
			t.Fatalf("AddRevocation with no signature: %v", err)
		}
	}
	if vs, err := s.Revocations(ctx, "person-a"); err != nil || len(vs) != 1 || len(vs[0].Signature) != 0 {
		t.Errorf("Revocations = %+v, %v; want the one, with no signature", vs, err)
	}
}

// refused checks that a write failed with an error of the database's and
// not one of the contract's.
func refused(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil || errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExists) {
		t.Errorf("%s: err = %v, want the database's refusal", what, err)
	}
}

// TestTimesAreWholeMicroseconds: the store stamps with its clock cut to
// the microsecond a timestamptz holds, so the time Append returns is the
// time the log reads back, and a time given with a part finer than that
// is compared exactly: what was stored at a time is not before it, and is
// before a nanosecond after it. Both query modes send times differently,
// binary truncating and text rounded by the server, and agree.
func TestTimesAreWholeMicroseconds(t *testing.T) {
	admin := server(t)
	for _, mode := range []string{"described", "exec"} {
		t.Run(mode, func(t *testing.T) {
			dsn := database(t, admin)
			o := postgres.Options{URL: dsn}
			if mode == "exec" {
				o.PoolURL = execMode(t, dsn)
			}
			s := open(t, o)
			ctx := t.Context()
			at := time.Date(2026, 10, 29, 12, 0, 0, 999_999_999, time.UTC)
			stored := time.Date(2026, 10, 29, 12, 0, 0, 999_999_000, time.UTC)
			postgres.SetClock(s, func() time.Time { return at })
			if err := s.CreateConversation(ctx, store.Conversation{ID: "c01", People: []string{"person-a"}}); err != nil {
				t.Fatal(err)
			}
			m, err := s.Append(ctx, "c01", 0, store.Append{
				Message:  store.Message{Kind: store.KindApplication, Person: "person-a", Device: "dev-a", Data: []byte("fake message")},
				Welcomes: []store.Welcome{{ID: "w-1", Person: "person-b", Device: "dev-b", Data: []byte("fake welcome")}},
			})
			if err != nil {
				t.Fatal(err)
			}
			msgs, err := s.Messages(ctx, "c01", 0, 10)
			if err != nil || len(msgs) != 1 {
				t.Fatalf("Messages = %+v, %v", msgs, err)
			}
			if !m.Created.Equal(stored) || !msgs[0].Created.Equal(m.Created) {
				t.Errorf("Append returned %v and the log holds %v, want both %v", m.Created, msgs[0].Created, stored)
			}
			c, err := s.Conversation(ctx, "c01")
			if err != nil || !c.Created.Equal(stored) || !c.Updated.Equal(stored) {
				t.Errorf("the conversation was created %v and updated %v, %v; want both %v", c.Created, c.Updated, err, stored)
			}

			if n, err := s.DeleteMessagesBefore(ctx, stored); err != nil || n != 0 {
				t.Errorf("DeleteMessagesBefore the time of the message = %d, %v; want 0 deleted", n, err)
			}
			if ws, err := s.Welcomes(ctx, "person-b", "dev-b"); err != nil || len(ws) != 1 {
				t.Errorf("Welcomes after deleting before their time = %+v, %v; want the one kept", ws, err)
			}
			if n, err := s.DeleteMessagesBefore(ctx, stored.Add(time.Nanosecond)); err != nil || n != 1 {
				t.Errorf("DeleteMessagesBefore a nanosecond after = %d, %v; want 1 deleted", n, err)
			}
			if ws, err := s.Welcomes(ctx, "person-b", "dev-b"); err != nil || len(ws) != 0 {
				t.Errorf("Welcomes after deleting past their time = %+v, %v; want none", ws, err)
			}

			given := time.Date(2026, 10, 28, 9, 30, 0, 123_456_789, time.UTC)
			if err := s.AddKeyPackages(ctx, []store.KeyPackage{{Ref: "01", Person: "person-a", Device: "dev-a", Created: given}}); err != nil {
				t.Fatal(err)
			}
			kp, err := s.ClaimKeyPackage(ctx, "person-a", "dev-a")
			if want := given.Truncate(time.Microsecond); err != nil || !kp.Created.Equal(want) {
				t.Errorf("a key package published at %v was handed out created %v, %v; want %v", given, kp.Created, err, want)
			}
		})
	}
}

// TestIDsSortByteByByte: ids list and page in the order Go compares
// strings, on a database whose collation orders text for people to read,
// where an upper-case letter sorts among the lower-case ones and a hyphen
// counts for less than a letter.
func TestIDsSortByteByByte(t *testing.T) {
	dsn := database(t, server(t), "template template0 locale_provider icu icu_locale 'und'")
	s := open(t, postgres.Options{URL: dsn})
	ctx := t.Context()
	ids := []string{"ab", "B", "a-c", "é", "Z", "a"}
	for _, id := range ids {
		if err := s.PutDevice(ctx, messaging.DeviceRecord{Person: "person-a", ID: id}, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateConversation(ctx, store.Conversation{ID: id, People: []string{"person-a"}}); err != nil {
			t.Fatal(err)
		}
	}
	want := slices.Sorted(slices.Values(ids))
	rs, err := s.Devices(ctx, "person-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := idsOf(rs, func(r messaging.DeviceRecord) string { return r.ID }); !slices.Equal(got, want) {
		t.Errorf("Devices = %q, want %q", got, want)
	}
	var paged []string
	for after := ""; ; {
		page, err := s.Conversations(ctx, "person-a", after, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		paged = append(paged, idsOf(page, func(c store.Conversation) string { return c.ID })...)
		after = page[len(page)-1].ID
	}
	if !slices.Equal(paged, want) {
		t.Errorf("Conversations two at a time = %q, want %q", paged, want)
	}
}

func idsOf[T any](xs []T, id func(T) string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = id(x)
	}
	return out
}

// TestEpochsKeepAllSixtyFourBits: an epoch is an unsigned 64-bit number,
// and the state, the log and the spans keep the largest one whole.
func TestEpochsKeepAllSixtyFourBits(t *testing.T) {
	s := open(t, postgres.Options{URL: database(t, server(t))})
	ctx := t.Context()
	c := store.Conversation{ID: "c01", People: []string{"person-a"}, Epoch: math.MaxUint64 - 1}
	if err := s.CreateConversation(ctx, c); err != nil {
		t.Fatal(err)
	}
	state := c
	state.Epoch = math.MaxUint64
	state.Members = []store.Member{{Person: "person-a", Device: "dev-a", Since: math.MaxUint64 - 1, Until: math.MaxUint64}}
	if _, err := s.Append(ctx, "c01", 0, store.Append{
		Message: store.Message{Kind: store.KindCommit, Epoch: math.MaxUint64 - 1, Data: []byte("fake commit")}, State: &state,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Conversation(ctx, "c01")
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != state.Epoch || !slices.Equal(got.Members, state.Members) {
		t.Errorf("the conversation reads epoch %d and members %+v, want %d and %+v", got.Epoch, got.Members, state.Epoch, state.Members)
	}
	msgs, err := s.Messages(ctx, "c01", 0, 1)
	if err != nil || len(msgs) != 1 || msgs[0].Epoch != math.MaxUint64-1 {
		t.Errorf("Messages = %+v, %v; want the commit of epoch %d", msgs, err, uint64(math.MaxUint64-1))
	}
}

// TestARowTheStoreCannotReadIsAnError: a row that does not read as a
// conversation, changed by hand or by a binary that wrote it otherwise,
// fails the read rather than reading as something else.
func TestARowTheStoreCannotReadIsAnError(t *testing.T) {
	dsn := database(t, server(t))
	s := open(t, postgres.Options{URL: dsn})
	ctx := t.Context()
	for _, id := range []string{"c01", "c02"} {
		if err := s.CreateConversation(ctx, store.Conversation{ID: id, People: []string{"person-a"}}); err != nil {
			t.Fatal(err)
		}
	}
	execute(t, dsn, `update conversations set members = '{"person": "person-a"}' where id = 'c01'`,
		`update conversations set epoch = -1 where id = 'c02'`)
	for _, id := range []string{"c01", "c02"} {
		if _, err := s.Conversation(ctx, id); err == nil || errors.Is(err, store.ErrNotFound) {
			t.Errorf("Conversation %s that does not read = %v, want an error", id, err)
		}
	}
	if _, err := s.Conversations(ctx, "person-a", "", 10); err == nil {
		t.Error("Conversations over rows that do not read reported no error")
	}
}

// TestPingAndClose: Ping answers while the store is open, and Close
// releases the pool, after which Ping and every method fail, with errors
// of the database's and not of the contract's.
func TestPingAndClose(t *testing.T) {
	s, err := postgres.Open(t.Context(), postgres.Options{URL: database(t, server(t))})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping of an open store: %v", err)
	}
	s.Close()
	s.Close() // a second Close is a no-op, as a shutdown path that runs twice needs
	if err := s.Ping(ctx); err == nil {
		t.Error("Ping of a closed store reported no error")
	}
	_, _, countErr := s.CountKeyPackages(ctx, "person-a", "dev-a")
	for what, err := range map[string]error{
		"PutDevice":            s.PutDevice(ctx, messaging.DeviceRecord{Person: "person-a", ID: "dev-a"}, nil),
		"Devices":              second(s.Devices(ctx, "person-a")),
		"AddRevocation":        s.AddRevocation(ctx, messaging.Revocation{Person: "person-a"}, "dev-a", nil),
		"Revocations":          second(s.Revocations(ctx, "person-a")),
		"PutRecovery":          s.PutRecovery(ctx, "person-a", []byte("fake wrapped key")),
		"Recovery":             second(s.Recovery(ctx, "person-a")),
		"PutTransfer":          s.PutTransfer(ctx, "person-a", "dev-a", []byte("fake sealed key")),
		"TakeTransfer":         second(s.TakeTransfer(ctx, "person-a", "dev-a")),
		"AddKeyPackages":       s.AddKeyPackages(ctx, []store.KeyPackage{{Ref: "01", Person: "person-a", Device: "dev-a"}}),
		"CountKeyPackages":     countErr,
		"ClaimKeyPackage":      second(s.ClaimKeyPackage(ctx, "person-a", "dev-a")),
		"CreateConversation":   s.CreateConversation(ctx, store.Conversation{ID: "c01"}),
		"Conversation":         second(s.Conversation(ctx, "c01")),
		"Conversations":        second(s.Conversations(ctx, "person-a", "", 10)),
		"Append":               second(s.Append(ctx, "c01", 0, store.Append{})),
		"Messages":             second(s.Messages(ctx, "c01", 0, 10)),
		"Messages, no limit":   second(s.Messages(ctx, "c01", 0, 0)),
		"Welcomes":             second(s.Welcomes(ctx, "person-a", "dev-a")),
		"DeleteWelcome":        s.DeleteWelcome(ctx, "person-a", "dev-a", "w-1"),
		"DeleteMessagesBefore": second(s.DeleteMessagesBefore(ctx, time.Now())),
	} {
		refused(t, err, what+" on a closed store")
	}
}

func second[T any](_ T, err error) error { return err }

// TestNothingLeavesTheBytesItWasHanded: every byte string a store is
// handed is ciphertext or a public key, and it is kept as bytes: a value
// planted in each is in no column of any other type, in no index key,
// and in no error of a refused write. A store that parsed what it holds,
// or logged it, or copied it into a text column, would show it here.
func TestNothingLeavesTheBytesItWasHanded(t *testing.T) {
	dsn := database(t, server(t))
	s := open(t, postgres.Options{URL: dsn})
	ctx := t.Context()
	canary := []byte("canary 6f1c2b: what people write to each other")
	planted := func(what string) []byte { return append(append([]byte(what+" "), canary...), 0xff) }
	if err := s.PutDevice(ctx, messaging.DeviceRecord{
		Person: "person-a", ID: "dev-a", Voucher: "dev-a",
		SignatureKey: planted("signature key"), EncryptionKey: planted("encryption key"), VoucherKey: planted("voucher key"),
		Vouch: planted("vouch"), Possession: planted("possession"),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRevocation(ctx, messaging.Revocation{
		Person: "person-a", By: "dev-a", Key: planted("revoked key"), Keep: [][]byte{planted("kept key")}, Signature: planted("signature"),
	}, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRecovery(ctx, "person-a", planted("wrapped backup key")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutTransfer(ctx, "person-a", "dev-b", planted("sealed backup key")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddKeyPackages(ctx, []store.KeyPackage{
		{Ref: "01", Person: "person-a", Device: "dev-a", Data: planted("key package")},
		{Ref: "02", Person: "person-a", Device: "dev-a", Data: planted("last resort"), LastResort: true},
	}); err != nil {
		t.Fatal(err)
	}
	c := store.Conversation{ID: "c01", People: []string{"person-a"}, View: planted("view"), GroupInfo: planted("group info"),
		Members: []store.Member{{Person: "person-a", Device: "dev-a"}}}
	if err := s.CreateConversation(ctx, c); err != nil {
		t.Fatal(err)
	}
	state := c
	state.View, state.GroupInfo = planted("next view"), planted("next group info")
	if _, err := s.Append(ctx, "c01", 0, store.Append{
		Message:  store.Message{Kind: store.KindCommit, Person: "person-a", Device: "dev-a", Data: planted("commit")},
		State:    &state,
		Welcomes: []store.Welcome{{ID: "w-1", Person: "person-b", Device: "dev-b", Data: planted("welcome"), Notice: planted("notice")}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, "c01", 1, store.Append{
		Message: store.Message{Kind: store.KindApplication, Person: "person-a", Device: "dev-a", Data: planted("message")},
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Append(ctx, "c01", 1, store.Append{
		Message:  store.Message{Kind: store.KindApplication, Person: "person-a", Device: "dev-a", Data: planted("refused message")},
		Welcomes: []store.Welcome{{ID: "w-\x00", Person: "person-b", Device: "dev-b", Data: planted("refused welcome")}},
	})
	if err == nil {
		t.Fatal("the append with a NUL in a welcome's id was not refused")
	}
	if strings.Contains(err.Error(), string(canary)) {
		t.Errorf("a refused append's error carries what it was handed: %q", err)
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			t.Errorf("closing the connection: %v", err)
		}
	}()
	rows, err := conn.Query(ctx, `
select table_name, column_name, udt_name from information_schema.columns
where table_schema = 'public' order by table_name, ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	type column struct{ table, name, udt string }
	columns, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (column, error) {
		var c column
		err := row.Scan(&c.table, &c.name, &c.udt)
		return c, err
	})
	if err != nil {
		t.Fatal(err)
	}
	inBytes := 0
	for _, col := range columns {
		ident := pgx.Identifier{col.table}.Sanitize() + "." + pgx.Identifier{col.name}.Sanitize()
		var n int
		switch col.udt {
		case "bytea":
			err = conn.QueryRow(ctx, `select count(*) from `+pgx.Identifier{col.table}.Sanitize()+` where position($1::bytea in `+ident+`) > 0`, canary).Scan(&n)
			inBytes += n
		case "_bytea":
			err = conn.QueryRow(ctx, `select count(*) from `+pgx.Identifier{col.table}.Sanitize()+`, unnest(`+ident+`) b where position($1::bytea in b) > 0`, canary).Scan(&n)
			inBytes += n
		default:
			err = conn.QueryRow(ctx, `select count(*) from `+pgx.Identifier{col.table}.Sanitize()+` where position($1 in `+ident+`::text) > 0`, string(canary)).Scan(&n)
			if n > 0 {
				t.Errorf("%s, a %s column, holds the value planted in bytes", ident, col.udt)
			}
		}
		if err != nil {
			t.Fatalf("searching %s: %v", ident, err)
		}
	}
	// Eighteen byte strings were kept: five of the record's, three of the
	// revocation's, the backup key, the transfer, two key packages, the
	// state's two, the commit, the message and the welcome's two.
	if inBytes != 18 {
		t.Errorf("the planted value is in %d byte strings, want the 18 that were kept: the search does not find what it looks for", inBytes)
	}
}
