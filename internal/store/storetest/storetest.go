// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package storetest is the contract of package store as one suite, which
// every implementation runs against stores of its own:
//
//	func TestContract(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) store.Store { return memory.New(nil) })
//	}
//
// The suite reads and writes through store.Store alone, so it holds an
// implementation to what the interface's doc comments promise and to
// nothing of how it keeps its state. Its fixtures are obviously fake
// bytes: a store keeps keys, records and messages and never reads them.
package storetest

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/internal/store"
)

// Run runs the contract against the stores open makes. open is called
// once for each subtest and returns an empty store. The subtests run one
// after another, so open may hand out one database emptied each time.
func Run(t *testing.T, open func(t *testing.T) store.Store) {
	t.Helper()
	for _, c := range []struct {
		name string
		test func(*testing.T, store.Store)
	}{
		{"Devices", testDevices},
		{"Revocations", testRevocations},
		{"RevocationDeletesKeys", testRevocationDeletesKeys},
		{"DirectoryCheck", testDirectoryCheck},
		{"DirectoryPutRace", testDirectoryPutRace},
		{"DirectoryRevocationRace", testDirectoryRevocationRace},
		{"DirectoryWritesOfBothKinds", testDirectoryWritesOfBothKinds},
		{"Recovery", testRecovery},
		{"Transfer", testTransfer},
		{"TransferTakenOnce", testTransferTakenOnce},
		{"KeyPackages", testKeyPackages},
		{"LastResort", testLastResort},
		{"KeyPackagesClaimedOnce", testKeyPackagesClaimedOnce},
		{"CreateConversation", testCreateConversation},
		{"Conversations", testConversations},
		{"Append", testAppend},
		{"AppendState", testAppendState},
		{"AppendConflict", testAppendConflict},
		{"AppendRace", testAppendRace},
		{"Messages", testMessages},
		{"Limits", testLimits},
		{"Welcomes", testWelcomes},
		{"DeleteMessagesBefore", testDeleteMessagesBefore},
		{"Spans", testSpans},
		{"Copies", testCopies},
	} {
		t.Run(c.name, func(t *testing.T) { c.test(t, open(t)) })
	}
}

// racers is how many goroutines a race between callers runs.
const racers = 8

// testDevices checks that a person's records list by id, that a record
// replaces the one with its id, and that a person's records are theirs.
func testDevices(t *testing.T, s store.Store) {
	ctx := t.Context()
	got, err := s.Devices(ctx, "person-a")
	must(t, err, "Devices")
	checkf(t, len(got) == 0, "Devices of a person with no record = %v, want none", each(got, recordID))

	a, b, c := device("person-a", "dev-a"), device("person-a", "dev-b"), device("person-a", "dev-c")
	rec := recovery("person-a", "rec-1", a)
	other := device("person-b", "dev-a")
	for _, r := range []messaging.DeviceRecord{c, rec, a, other, b} {
		must(t, s.PutDevice(ctx, r, nil), "PutDevice "+r.Person+"/"+r.ID)
	}
	got, err = s.Devices(ctx, "person-a")
	must(t, err, "Devices")
	checkf(t, slices.EqualFunc(got, []messaging.DeviceRecord{a, b, c, rec}, sameRecord),
		"Devices = %v, want dev-a, dev-b, dev-c and rec-1 as they were put, by id", each(got, recordID))

	b.EncryptionKey = fake("rotated encryption key", "person-a", "dev-b")
	must(t, s.PutDevice(ctx, b, nil), "PutDevice of an id the person has")
	got, err = s.Devices(ctx, "person-a")
	must(t, err, "Devices")
	checkf(t, slices.EqualFunc(got, []messaging.DeviceRecord{a, b, c, rec}, sameRecord),
		"Devices after a record was put again = %v, want dev-b replaced and nothing added", each(got, recordID))

	got, err = s.Devices(ctx, "person-b")
	must(t, err, "Devices")
	checkf(t, slices.EqualFunc(got, []messaging.DeviceRecord{other}, sameRecord),
		"Devices of person-b = %v, want their one record, apart from person-a's of the same id", each(got, recordID))
}

// testRevocations checks that revocations list in the order they were
// first added, once each however often they are added, per person.
func testRevocations(t *testing.T, s store.Store) {
	ctx := t.Context()
	got, err := s.Revocations(ctx, "person-a")
	must(t, err, "Revocations")
	checkf(t, len(got) == 0, "Revocations of a person with none = %v, want none", each(got, revokedBy))

	first, second := revocation("person-a", "dev-c"), revocation("person-a", "dev-b", "dev-d", "dev-e")
	for _, v := range []messaging.Revocation{first, second, first, revocation("person-b", "dev-a"), second} {
		must(t, s.AddRevocation(ctx, v, "", nil), "AddRevocation by "+v.Person+"/"+v.By)
	}
	got, err = s.Revocations(ctx, "person-a")
	must(t, err, "Revocations")
	checkf(t, slices.EqualFunc(got, []messaging.Revocation{first, second}, sameRevocation),
		"Revocations = %v, want dev-c's then dev-b's, once each", each(got, revokedBy))
	got, err = s.Revocations(ctx, "person-b")
	must(t, err, "Revocations")
	checkf(t, slices.EqualFunc(got, []messaging.Revocation{revocation("person-b", "dev-a")}, sameRevocation),
		"Revocations of person-b = %v, want their one", each(got, revokedBy))
}

// testRevocationDeletesKeys checks that a revocation naming a device
// deletes that device's key packages and transfer and nothing of any
// other device, and that one naming none deletes nothing.
func testRevocationDeletesKeys(t *testing.T, s store.Store) {
	ctx := t.Context()
	for _, d := range [][2]string{{"person-a", "dev-b"}, {"person-a", "dev-c"}, {"person-b", "dev-b"}} {
		publish(t, s, d[0], d[1])
	}
	must(t, s.AddRevocation(ctx, revocation("person-a", "dev-b"), "dev-b", nil), "AddRevocation of dev-b")
	gone(t, s, "person-a", "dev-b")
	count(t, s, "person-a", "dev-c", 2, true)
	count(t, s, "person-b", "dev-b", 2, true)

	must(t, s.AddRevocation(ctx, revocation("person-a", "rec-1"), "", nil), "AddRevocation that names no device")
	count(t, s, "person-a", "dev-c", 2, true)
	count(t, s, "person-b", "dev-b", 2, true)

	// Added again, the revocation is kept once and still deletes what the
	// device published since.
	publish(t, s, "person-a", "dev-b")
	must(t, s.AddRevocation(ctx, revocation("person-a", "dev-b"), "dev-b", nil), "AddRevocation of dev-b again")
	gone(t, s, "person-a", "dev-b")
	got, err := s.Revocations(ctx, "person-a")
	must(t, err, "Revocations")
	checkf(t, slices.EqualFunc(got, []messaging.Revocation{revocation("person-a", "dev-b"), revocation("person-a", "rec-1")}, sameRevocation),
		"Revocations = %v, want dev-b's and rec-1's once each", each(got, revokedBy))

	for _, d := range [][2]string{{"person-a", "dev-c"}, {"person-b", "dev-b"}} {
		sealed, err := s.TakeTransfer(ctx, d[0], d[1])
		must(t, err, "TakeTransfer of "+d[0]+"/"+d[1]+", which no revocation named")
		checkf(t, bytes.Equal(sealed, fake("sealed backup key", d[0], d[1])), "TakeTransfer of %s/%s = %q", d[0], d[1], sealed)
	}
}

// errRefused is a directory check's refusal, which the write returns as
// it is.
var errRefused = errors.New("storetest: the check refused the write")

// testDirectoryCheck checks that a directory write's check is given the
// person's records and revocations, and decides the write: true writes,
// false writes nothing, and an error writes nothing and is the write's,
// unchanged. What check is given is its own to change.
func testDirectoryCheck(t *testing.T, s store.Store) {
	ctx := t.Context()
	a, b := device("person-a", "dev-a"), device("person-a", "dev-b")
	first := revocation("person-a", "dev-c")
	must(t, s.PutDevice(ctx, a, nil), "PutDevice with no check")
	must(t, s.AddRevocation(ctx, first, "", nil), "AddRevocation with no check")
	must(t, s.PutDevice(ctx, device("person-b", "dev-a"), nil), "PutDevice of another person")
	publish(t, s, "person-a", "dev-b")

	var seen [][]string
	look := func(write bool, err error) store.DirectoryCheck {
		return func(records []messaging.DeviceRecord, revocations []messaging.Revocation) (bool, error) {
			seen = append(seen, append(each(records, recordID), each(revocations, revokedBy)...))
			for i := range records {
				clear(records[i].SignatureKey)
			}
			for i := range revocations {
				clear(revocations[i].Signature)
			}
			return write, err
		}
	}
	must(t, s.PutDevice(ctx, b, look(true, nil)), "PutDevice its check allows")
	checkf(t, slices.Equal(seen[len(seen)-1], []string{"dev-a", "dev-c"}), "the check of a PutDevice saw %v, want person-a's record dev-a and revocation by dev-c", seen[len(seen)-1])
	err := s.PutDevice(ctx, device("person-a", "dev-d"), look(false, errRefused))
	checkf(t, errors.Is(err, errRefused) && err.Error() == errRefused.Error(), "PutDevice its check refuses: err = %v, want the check's, unchanged", err)
	checkf(t, slices.Equal(seen[len(seen)-1], []string{"dev-a", "dev-b", "dev-c"}), "the check of a PutDevice after another saw %v, want dev-a, dev-b and the revocation by dev-c", seen[len(seen)-1])
	must(t, s.PutDevice(ctx, device("person-a", "dev-e"), look(false, nil)), "PutDevice its check passes over")
	got, err := s.Devices(ctx, "person-a")
	must(t, err, "Devices")
	checkf(t, slices.EqualFunc(got, []messaging.DeviceRecord{a, b}, sameRecord),
		"Devices = %v, want dev-a and dev-b as they were put, and nothing a check refused or passed over", each(got, recordID))

	second := revocation("person-a", "dev-b")
	err = s.AddRevocation(ctx, second, "dev-b", look(false, errRefused))
	checkf(t, errors.Is(err, errRefused) && err.Error() == errRefused.Error(), "AddRevocation its check refuses: err = %v, want the check's, unchanged", err)
	must(t, s.AddRevocation(ctx, second, "dev-b", look(false, nil)), "AddRevocation its check passes over")
	count(t, s, "person-a", "dev-b", 2, true)
	must(t, s.AddRevocation(ctx, second, "dev-b", look(true, nil)), "AddRevocation its check allows")
	gone(t, s, "person-a", "dev-b")
	vs, err := s.Revocations(ctx, "person-a")
	must(t, err, "Revocations")
	checkf(t, slices.EqualFunc(vs, []messaging.Revocation{first, second}, sameRevocation),
		"Revocations = %v, want dev-c's and then dev-b's, kept once its check allowed it", each(vs, revokedBy))
}

// testDirectoryPutRace checks that of records put at once under one new
// id, each with a check that refuses an id already listed, exactly one is
// written: no check reads the directory another write is deciding from.
func testDirectoryPutRace(t *testing.T, s store.Store) {
	ctx := t.Context()
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		r := device("person-a", "dev-x")
		r.SignatureKey = fake("signature key", "person-a", "dev-x", strconv.Itoa(i))
		wg.Go(func() {
			errs[i] = s.PutDevice(ctx, r, func(records []messaging.DeviceRecord, _ []messaging.Revocation) (bool, error) {
				if slices.ContainsFunc(records, func(o messaging.DeviceRecord) bool { return o.ID == r.ID }) {
					return false, errRefused
				}
				// A check that takes a moment, as one that verifies
				// signatures does, gives a write that did not wait for it
				// the time to land.
				time.Sleep(5 * time.Millisecond)
				return true, nil
			})
		})
	}
	wg.Wait()
	won, refused := -1, 0
	for i, err := range errs {
		switch {
		case err == nil:
			won = i
		case errors.Is(err, errRefused):
			refused++
		}
	}
	requiref(t, won >= 0 && refused == racers-1, "%d of %d puts of one new id were refused, want all but one: %v", refused, racers, errs)
	got, err := s.Devices(ctx, "person-a")
	must(t, err, "Devices")
	checkf(t, len(got) == 1 && bytes.Equal(got[0].SignatureKey, fake("signature key", "person-a", "dev-x", strconv.Itoa(won))),
		"Devices after the race = %v, want the one put that was not refused", each(got, recordID))
}

// testDirectoryRevocationRace checks that of revocations added at once,
// each with a check that holds a person to one revocation, exactly one is
// kept.
func testDirectoryRevocationRace(t *testing.T, s store.Store) {
	ctx := t.Context()
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		v := revocation("person-a", "dev-"+strconv.Itoa(i))
		wg.Go(func() {
			errs[i] = s.AddRevocation(ctx, v, "", func(_ []messaging.DeviceRecord, revocations []messaging.Revocation) (bool, error) {
				if len(revocations) >= 1 {
					return false, errRefused
				}
				time.Sleep(5 * time.Millisecond)
				return true, nil
			})
		})
	}
	wg.Wait()
	kept := 0
	for _, err := range errs {
		if err == nil {
			kept++
		}
	}
	got, err := s.Revocations(ctx, "person-a")
	must(t, err, "Revocations")
	checkf(t, kept == 1 && len(got) == 1, "%d of %d revocations bound to one were kept, and the person has %v, want one: %v", kept, racers, each(got, revokedBy), errs)
}

// testDirectoryWritesOfBothKinds checks that a record put and a
// revocation added at once for one person decide one after the other: a
// check that allows one write to a person's whole directory lets one of
// them through.
func testDirectoryWritesOfBothKinds(t *testing.T, s store.Store) {
	ctx := t.Context()
	once := func(records []messaging.DeviceRecord, revocations []messaging.Revocation) (bool, error) {
		if len(records)+len(revocations) >= 1 {
			return false, errRefused
		}
		time.Sleep(5 * time.Millisecond)
		return true, nil
	}
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		id := "dev-" + strconv.Itoa(i)
		wg.Go(func() {
			if i%2 == 0 {
				errs[i] = s.PutDevice(ctx, device("person-a", id), once)
			} else {
				errs[i] = s.AddRevocation(ctx, revocation("person-a", id), "", once)
			}
		})
	}
	wg.Wait()
	rs, err := s.Devices(ctx, "person-a")
	must(t, err, "Devices")
	vs, err := s.Revocations(ctx, "person-a")
	must(t, err, "Revocations")
	checkf(t, len(rs)+len(vs) == 1, "records %v and revocations %v were written, want one write of either: %v", each(rs, recordID), each(vs, revokedBy), errs)
}

// testRecovery checks that a wrapped backup key is kept per person and
// replaced by the next.
func testRecovery(t *testing.T, s store.Store) {
	ctx := t.Context()
	_, err := s.Recovery(ctx, "person-a")
	is(t, err, store.ErrNotFound, "Recovery of a person with none")

	first, second := fake("wrapped backup key", "person-a", "1"), fake("wrapped backup key", "person-a", "2")
	must(t, s.PutRecovery(ctx, "person-a", first), "PutRecovery")
	got, err := s.Recovery(ctx, "person-a")
	must(t, err, "Recovery")
	checkf(t, bytes.Equal(got, first), "Recovery = %q, want %q", got, first)

	must(t, s.PutRecovery(ctx, "person-a", second), "PutRecovery again")
	got, err = s.Recovery(ctx, "person-a")
	must(t, err, "Recovery")
	checkf(t, bytes.Equal(got, second), "Recovery after a replace = %q, want %q", got, second)

	_, err = s.Recovery(ctx, "person-b")
	is(t, err, store.ErrNotFound, "Recovery of another person")
}

// testTransfer checks that a transfer is left per device, replaced by
// the next, and taken once.
func testTransfer(t *testing.T, s store.Store) {
	ctx := t.Context()
	_, err := s.TakeTransfer(ctx, "person-a", "dev-b")
	is(t, err, store.ErrNotFound, "TakeTransfer with nothing left")

	first, second := fake("sealed backup key", "person-a", "dev-b", "1"), fake("sealed backup key", "person-a", "dev-b", "2")
	other := fake("sealed backup key", "person-a", "dev-c")
	must(t, s.PutTransfer(ctx, "person-a", "dev-b", first), "PutTransfer")
	must(t, s.PutTransfer(ctx, "person-a", "dev-b", second), "PutTransfer again")
	must(t, s.PutTransfer(ctx, "person-a", "dev-c", other), "PutTransfer to another device")

	_, err = s.TakeTransfer(ctx, "person-b", "dev-b")
	is(t, err, store.ErrNotFound, "TakeTransfer for another person's device of the same id")
	got, err := s.TakeTransfer(ctx, "person-a", "dev-b")
	must(t, err, "TakeTransfer")
	checkf(t, bytes.Equal(got, second), "TakeTransfer = %q, want the later one, %q", got, second)
	_, err = s.TakeTransfer(ctx, "person-a", "dev-b")
	is(t, err, store.ErrNotFound, "TakeTransfer a second time")
	got, err = s.TakeTransfer(ctx, "person-a", "dev-c")
	must(t, err, "TakeTransfer for the other device")
	checkf(t, bytes.Equal(got, other), "TakeTransfer for the other device = %q, want %q", got, other)
}

// testTransferTakenOnce checks that of callers taking one transfer at
// once, exactly one gets it.
func testTransferTakenOnce(t *testing.T, s store.Store) {
	ctx := t.Context()
	sealed := fake("sealed backup key", "person-a", "dev-b")
	must(t, s.PutTransfer(ctx, "person-a", "dev-b", sealed), "PutTransfer")
	got := make([][]byte, racers)
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() { got[i], errs[i] = s.TakeTransfer(ctx, "person-a", "dev-b") })
	}
	wg.Wait()
	taken, missed := 0, 0
	for i, err := range errs {
		switch {
		case err == nil && bytes.Equal(got[i], sealed):
			taken++
		case errors.Is(err, store.ErrNotFound):
			missed++
		}
	}
	checkf(t, taken == 1 && missed == racers-1, "%d of %d takes got the transfer and %d found none, want 1 and %d: %v", taken, racers, missed, racers-1, errs)
}

// testKeyPackages checks that one-time key packages are counted and
// handed out oldest first, each once, per device.
func testKeyPackages(t *testing.T, s store.Store) {
	ctx := t.Context()
	count(t, s, "person-a", "dev-a", 0, false)
	_, err := s.ClaimKeyPackage(ctx, "person-a", "dev-a")
	is(t, err, store.ErrNotFound, "ClaimKeyPackage of a device that published none")

	// Published one call apiece, so which is oldest is plain.
	kps := []store.KeyPackage{
		keyPackage("person-a", "dev-a", "1", false), keyPackage("person-a", "dev-a", "2", false), keyPackage("person-a", "dev-a", "3", false),
	}
	for _, kp := range kps {
		must(t, s.AddKeyPackages(ctx, []store.KeyPackage{kp}), "AddKeyPackages")
	}
	must(t, s.AddKeyPackages(ctx, []store.KeyPackage{keyPackage("person-a", "dev-b", "1", false), keyPackage("person-b", "dev-a", "1", false)}),
		"AddKeyPackages for two devices")
	count(t, s, "person-a", "dev-a", 3, false)
	for i, kp := range kps {
		claim(t, s, kp, "the oldest left")
		count(t, s, "person-a", "dev-a", len(kps)-i-1, false)
	}
	_, err = s.ClaimKeyPackage(ctx, "person-a", "dev-a")
	is(t, err, store.ErrNotFound, "ClaimKeyPackage of a device whose packages were all claimed")
	count(t, s, "person-a", "dev-b", 1, false)
	count(t, s, "person-b", "dev-a", 1, false)
}

// testLastResort checks that a last resort is handed out once the
// one-time packages are gone, kept when it is, and replaced by the next.
func testLastResort(t *testing.T, s store.Store) {
	ctx := t.Context()
	once, resort := keyPackage("person-a", "dev-a", "1", false), keyPackage("person-a", "dev-a", "last-1", true)
	must(t, s.AddKeyPackages(ctx, []store.KeyPackage{resort, once}), "AddKeyPackages")
	count(t, s, "person-a", "dev-a", 1, true)
	claim(t, s, once, "a one-time package before the last resort")
	count(t, s, "person-a", "dev-a", 0, true)
	claim(t, s, resort, "the last resort")
	claim(t, s, resort, "the last resort, which a claim keeps")
	count(t, s, "person-a", "dev-a", 0, true)

	replaced := keyPackage("person-a", "dev-a", "last-2", true)
	must(t, s.AddKeyPackages(ctx, []store.KeyPackage{replaced}), "AddKeyPackages of another last resort")
	count(t, s, "person-a", "dev-a", 0, true)
	claim(t, s, replaced, "the later last resort")

	later := keyPackage("person-a", "dev-a", "2", false)
	must(t, s.AddKeyPackages(ctx, []store.KeyPackage{later}), "AddKeyPackages after the last resort")
	count(t, s, "person-a", "dev-a", 1, true)
	claim(t, s, later, "a one-time package published after the last resort")
	claim(t, s, replaced, "the last resort again")
}

// testKeyPackagesClaimedOnce checks that of callers claiming one
// device's packages at once, each package goes to one of them.
func testKeyPackagesClaimedOnce(t *testing.T, s store.Store) {
	ctx := t.Context()
	var kps []store.KeyPackage
	for i := range racers {
		kps = append(kps, keyPackage("person-a", "dev-a", strconv.Itoa(i), false))
	}
	must(t, s.AddKeyPackages(ctx, kps), "AddKeyPackages")
	got := make([]store.KeyPackage, 2*racers)
	errs := make([]error, 2*racers)
	var wg sync.WaitGroup
	for i := range 2 * racers {
		wg.Go(func() { got[i], errs[i] = s.ClaimKeyPackage(ctx, "person-a", "dev-a") })
	}
	wg.Wait()
	refs := map[string]bool{}
	handed, missed := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			handed++
			refs[got[i].Ref] = true
		case errors.Is(err, store.ErrNotFound):
			missed++
		}
	}
	checkf(t, handed == racers && len(refs) == racers && missed == racers,
		"%d claims got %d distinct packages and %d found none, want %d, %d and %d: %v", handed, len(refs), missed, racers, racers, racers, errs)
}

// testCreateConversation checks that a conversation reads back as it was
// created, with no message and no change yet, and that its id is taken.
func testCreateConversation(t *testing.T, s store.Store) {
	ctx := t.Context()
	_, err := s.Conversation(ctx, "c01")
	is(t, err, store.ErrNotFound, "Conversation before it is created")

	group := conversation("c01", "person-a", "person-b")
	pair := conversation("c02", "person-a", "person-c")
	pair.Kind, pair.Level = messaging.KindOneOnOne, messaging.LevelTakesPart
	for _, c := range []store.Conversation{group, pair} {
		must(t, s.CreateConversation(ctx, c), "CreateConversation "+c.ID)
		got, err := s.Conversation(ctx, c.ID)
		must(t, err, "Conversation "+c.ID)
		checkf(t, sameState(got, c), "Conversation = %+v, want the state it was created with, %+v", got, c)
		checkf(t, got.Seq == 0 && got.Version == 0, "a new conversation has seq %d and version %d, want 0 and 0", got.Seq, got.Version)
		checkf(t, !got.Created.IsZero() && !got.Updated.IsZero(), "a new conversation was created at %v and updated at %v, want both set", got.Created, got.Updated)
	}

	is(t, s.CreateConversation(ctx, conversation("c01", "person-d")), store.ErrExists, "CreateConversation of an id that is taken")
	got, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	checkf(t, sameState(got, group), "a refused create changed the conversation: %+v", got)

	// The sequence number, the version and the times are the store's, so a
	// conversation handed in with its own starts with no message and no
	// change all the same.
	handed := conversation("c03", "person-a")
	handed.Seq, handed.Version, handed.Created, handed.Updated = 41, 7, time.Unix(0, 0), time.Unix(0, 0)
	must(t, s.CreateConversation(ctx, handed), "CreateConversation with a seq, a version and times of its own")
	got, err = s.Conversation(ctx, "c03")
	must(t, err, "Conversation")
	checkf(t, got.Seq == 0 && got.Version == 0, "a conversation created with seq 41 and version 7 has seq %d and version %d, want 0 and 0", got.Seq, got.Version)
	checkf(t, !got.Created.Equal(handed.Created) && !got.Updated.Equal(handed.Updated), "a conversation kept the times it was handed: created %v, updated %v", got.Created, got.Updated)
	m, err := s.Append(ctx, "c03", 0, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", "first")})
	must(t, err, "Append at version 0")
	checkf(t, m.Seq == 1, "the first message has seq %d, want 1", m.Seq)
}

// testConversations checks that a person's conversations list by id,
// after the id given and no more than the limit, and that the list
// follows the people of the state that stands.
func testConversations(t *testing.T, s store.Store) {
	ctx := t.Context()
	first := conversation("c01", "person-a", "person-b")
	for _, c := range []store.Conversation{
		conversation("c04", "person-a", "person-c"), first, conversation("c05", "person-c"),
		conversation("c03", "person-b", "person-a"), conversation("c02", "person-b"),
	} {
		must(t, s.CreateConversation(ctx, c), "CreateConversation "+c.ID)
	}
	for _, page := range []struct {
		person, after string
		limit         int
		want          []string
	}{
		{"person-a", "", 10, []string{"c01", "c03", "c04"}},
		{"person-a", "", 2, []string{"c01", "c03"}},
		{"person-a", "c03", 2, []string{"c04"}},
		{"person-a", "c02", 10, []string{"c03", "c04"}},
		{"person-a", "c04", 10, nil},
		{"person-b", "", 1, []string{"c01"}},
		{"person-d", "", 10, nil},
	} {
		got, err := s.Conversations(ctx, page.person, page.after, page.limit)
		must(t, err, "Conversations")
		checkf(t, slices.Equal(each(got, conversationID), page.want), "Conversations(%s, after %q, limit %d) = %v, want %v",
			page.person, page.after, page.limit, each(got, conversationID), page.want)
	}

	c, err := s.Conversation(ctx, "c03")
	must(t, err, "Conversation")
	left := commit(c, 1, []string{"person-b"}, store.Member{Person: "person-b", Device: "dev-a"})
	_, err = s.Append(ctx, "c03", c.Version, store.Append{Message: msg(store.KindCommit, 0, "person-b", "dev-a", "remove person-a"), State: left})
	must(t, err, "Append of a commit that removes person-a")
	got, err := s.Conversations(ctx, "person-a", "", 10)
	must(t, err, "Conversations")
	checkf(t, slices.Equal(each(got, conversationID), []string{"c01", "c04"}), "Conversations of person-a after they left c03 = %v, want c01 and c04", each(got, conversationID))
	checkf(t, len(got) > 0 && sameState(got[0], first), "a listed conversation = %+v, want its whole state, %+v", got, first)
}

// testAppend checks that messages take the next sequence numbers, that a
// message without a state leaves the state and its version alone, and
// that an append to no conversation is not found.
func testAppend(t *testing.T, s store.Store) {
	ctx := t.Context()
	c := conversation("c01", "person-a", "person-b")
	must(t, s.CreateConversation(ctx, c), "CreateConversation")
	created, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")

	first := msg(store.KindApplication, 0, "person-a", "dev-a", "first")
	m1, err := s.Append(ctx, "c01", 0, store.Append{Message: first})
	must(t, err, "Append")
	first.Conversation, first.Seq = "c01", 1
	checkf(t, sameMessage(m1, first) && !m1.Created.IsZero(), "Append = %+v, want %+v with the time it was stored", m1, first)

	second := msg(store.KindApplication, 0, "person-b", "dev-a", "second")
	m2, err := s.Append(ctx, "c01", 0, store.Append{Message: second})
	must(t, err, "Append at the version that still stands")
	checkf(t, m2.Seq == 2, "the second message has seq %d, want 2", m2.Seq)

	got, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	checkf(t, got.Seq == 2 && got.Version == 0 && sameState(got, c), "after two messages the conversation is %+v, want seq 2, version 0 and its state", got)
	checkf(t, got.Created.Equal(created.Created), "the conversation's creation moved from %v to %v", created.Created, got.Created)
	msgs, err := s.Messages(ctx, "c01", 0, 10)
	must(t, err, "Messages")
	checkf(t, slices.EqualFunc(msgs, []store.Message{m1, m2}, sameMessage), "Messages = %+v, want the two appended", msgs)

	_, err = s.Append(ctx, "c02", 0, store.Append{Message: first})
	is(t, err, store.ErrNotFound, "Append to a conversation that does not exist")
}

// testAppendState checks that an append's state replaces the
// conversation's apart from the id, the sequence number, the version and
// the creation, which stay the store's, and that a commit's welcomes are
// filed with its sequence number.
func testAppendState(t *testing.T, s store.Store) {
	ctx := t.Context()
	must(t, s.CreateConversation(ctx, conversation("c01", "person-a")), "CreateConversation")
	before, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")

	// A proposal of the service's own has no sender, and its state names
	// an id, a sequence number, a version and a time of its own.
	view := proposed(before, "1")
	view.ID, view.Seq, view.Version, view.Created = "c99", 41, 41, time.Unix(0, 0)
	m1, err := s.Append(ctx, "c01", before.Version, store.Append{Message: msg(store.KindProposal, 0, "", "", "remove a revoked leaf"), State: view})
	must(t, err, "Append of a proposal")
	checkf(t, m1.Seq == 1 && m1.Person == "" && m1.Device == "", "Append of the service's proposal = %+v, want seq 1 and no sender", m1)
	got, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	view.ID = "c01"
	checkf(t, sameState(got, *view), "after a proposal the conversation is %+v, want the proposal's state", got)
	checkf(t, got.Seq == 1 && got.Version == before.Version+1, "after a proposal seq %d and version %d, want 1 and %d", got.Seq, got.Version, before.Version+1)
	checkf(t, got.Created.Equal(before.Created), "a proposal moved the conversation's creation from %v to %v", before.Created, got.Created)
	_, err = s.Conversation(ctx, "c99")
	is(t, err, store.ErrNotFound, "Conversation of the id the proposal's state named")

	added := commit(got, 1, []string{"person-a", "person-b"},
		store.Member{Person: "person-a", Device: "dev-a"}, store.Member{Person: "person-b", Device: "dev-b", Since: 1})
	w := welcome("w-1", "person-b", "dev-b")
	m2, err := s.Append(ctx, "c01", got.Version, store.Append{
		Message: msg(store.KindCommit, 0, "person-a", "dev-a", "add person-b"), State: added, Welcomes: []store.Welcome{w},
	})
	must(t, err, "Append of a commit")
	got, err = s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	checkf(t, sameState(got, *added), "after a commit the conversation is %+v, want the commit's state", got)
	checkf(t, got.Seq == 2 && got.Version == before.Version+2, "after a commit seq %d and version %d, want 2 and %d", got.Seq, got.Version, before.Version+2)
	ws, err := s.Welcomes(ctx, "person-b", "dev-b")
	must(t, err, "Welcomes")
	w.Conversation, w.Seq = "c01", m2.Seq
	checkf(t, len(ws) == 1 && sameWelcome(ws[0], w) && !ws[0].Created.IsZero(), "Welcomes = %+v, want %+v filed at the time of the commit", ws, w)

	m3, err := s.Append(ctx, "c01", got.Version, store.Append{Message: msg(store.KindApplication, 1, "person-b", "dev-b", "hello")})
	must(t, err, "Append of a message after the commit")
	after, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	checkf(t, m3.Seq == 3 && after.Seq == 3 && after.Version == got.Version && sameState(after, *added),
		"a message after the commit made seq %d and the conversation %+v, want seq 3 and the commit's state and version", m3.Seq, after)
}

// testAppendConflict checks that an append read at a version that no
// longer stands is refused whole: no message, no state, no welcome.
func testAppendConflict(t *testing.T, s store.Store) {
	ctx := t.Context()
	c := conversation("c01", "person-a")
	must(t, s.CreateConversation(ctx, c), "CreateConversation")
	_, err := s.Append(ctx, "c01", 0, store.Append{Message: msg(store.KindProposal, 0, "person-a", "dev-a", "1"), State: proposed(c, "1")})
	must(t, err, "Append of a proposal")

	stale := store.Append{
		Message: msg(store.KindCommit, 0, "person-a", "dev-a", "add person-b"),
		State: commit(c, 1, []string{"person-a", "person-b"},
			store.Member{Person: "person-a", Device: "dev-a"}, store.Member{Person: "person-b", Device: "dev-b", Since: 1}),
		Welcomes: []store.Welcome{welcome("w-1", "person-b", "dev-b")},
	}
	_, err = s.Append(ctx, "c01", 0, stale)
	is(t, err, store.ErrConflict, "Append of a commit read before a proposal")
	_, err = s.Append(ctx, "c01", 0, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", "late")})
	is(t, err, store.ErrConflict, "Append of a message read before a proposal")
	_, err = s.Append(ctx, "c01", 2, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", "early")})
	is(t, err, store.ErrConflict, "Append at a version not reached")

	got, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	checkf(t, got.Version == 1 && got.Seq == 1 && sameState(got, *proposed(c, "1")), "refused appends changed the conversation: %+v", got)
	msgs, err := s.Messages(ctx, "c01", 0, 10)
	must(t, err, "Messages")
	checkf(t, slices.Equal(each(msgs, seqOf), []int64{1}), "after refused appends the log is %v, want the proposal alone", each(msgs, seqOf))
	ws, err := s.Welcomes(ctx, "person-b", "dev-b")
	must(t, err, "Welcomes")
	checkf(t, len(ws) == 0, "a refused commit filed welcomes %v", each(ws, welcomeID))

	m, err := s.Append(ctx, "c01", got.Version, stale)
	must(t, err, "Append of the commit at the version that stands")
	checkf(t, m.Seq == 2, "the commit has seq %d, want 2", m.Seq)
}

// testAppendRace checks that of appends racing from one version, the
// one with a state that lands first wins and the rest conflict, and that
// messages racing at one version each take a sequence number of their
// own.
func testAppendRace(t *testing.T, s store.Store) {
	ctx := t.Context()
	c := conversation("c01", "person-a")
	must(t, s.CreateConversation(ctx, c), "CreateConversation")
	ms := make([]store.Message, racers)
	errs := make([]error, racers)
	var wg sync.WaitGroup
	for i := range racers {
		label := strconv.Itoa(i)
		wg.Go(func() {
			ms[i], errs[i] = s.Append(ctx, "c01", 0, store.Append{Message: msg(store.KindProposal, 0, "person-a", "dev-a", label), State: proposed(c, label)})
		})
	}
	wg.Wait()
	winner, conflicts := -1, 0
	for i, err := range errs {
		switch {
		case err == nil:
			winner = i
		case errors.Is(err, store.ErrConflict):
			conflicts++
		}
	}
	requiref(t, winner >= 0 && conflicts == racers-1, "%d of %d proposals from one version conflicted, want all but one: %v", conflicts, racers, errs)
	got, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	checkf(t, got.Version == 1 && got.Seq == 1 && ms[winner].Seq == 1 && sameState(got, *proposed(c, strconv.Itoa(winner))),
		"after the race the conversation is %+v, want the winner's state at version 1", got)

	for i := range racers {
		label := strconv.Itoa(i)
		wg.Go(func() {
			ms[i], errs[i] = s.Append(ctx, "c01", 1, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", label)})
		})
	}
	wg.Wait()
	want := []int64{1}
	for i, err := range errs {
		must(t, err, "Append of a message racing at the version that stands")
		want = append(want, int64(i)+2)
	}
	msgs, err := s.Messages(ctx, "c01", 0, 2*racers)
	must(t, err, "Messages")
	checkf(t, slices.Equal(each(msgs, seqOf), want), "after the race the log is %v, want %v", each(msgs, seqOf), want)
	slices.SortFunc(ms, func(a, b store.Message) int { return cmp.Compare(a.Seq, b.Seq) })
	checkf(t, slices.Equal(each(ms, seqOf), want[1:]), "the racing appends returned seqs %v, want %v", each(ms, seqOf), want[1:])
}

// testMessages checks that a conversation's messages page by sequence
// number, oldest first, and that the numbers are the conversation's own.
func testMessages(t *testing.T, s store.Store) {
	ctx := t.Context()
	for _, id := range []string{"c01", "c02"} {
		must(t, s.CreateConversation(ctx, conversation(id, "person-a")), "CreateConversation "+id)
	}
	var all []store.Message
	for i, epoch := range []uint64{0, 0, 1, 1, 2} {
		m, err := s.Append(ctx, "c01", 0, store.Append{Message: msg(store.KindApplication, epoch, "person-a", "dev-a", strconv.Itoa(i))})
		must(t, err, "Append")
		all = append(all, m)
	}
	other, err := s.Append(ctx, "c02", 0, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", "other")})
	must(t, err, "Append to another conversation")
	checkf(t, other.Seq == 1, "the first message of another conversation has seq %d, want 1", other.Seq)

	for _, page := range []struct {
		after int64
		limit int
		want  []int64
	}{
		{0, 10, []int64{1, 2, 3, 4, 5}},
		{0, 2, []int64{1, 2}},
		{2, 2, []int64{3, 4}},
		{4, 2, []int64{5}},
		{5, 2, nil},
		{3, 10, []int64{4, 5}},
	} {
		got, err := s.Messages(ctx, "c01", page.after, page.limit)
		must(t, err, "Messages")
		checkf(t, slices.Equal(each(got, seqOf), page.want), "Messages(after %d, limit %d) = %v, want %v", page.after, page.limit, each(got, seqOf), page.want)
	}
	got, err := s.Messages(ctx, "c01", 0, 10)
	must(t, err, "Messages")
	checkf(t, slices.EqualFunc(got, all, sameMessage), "Messages = %+v, want them as they were appended, %+v", got, all)
	got, err = s.Messages(ctx, "c02", 0, 10)
	must(t, err, "Messages of another conversation")
	checkf(t, slices.EqualFunc(got, []store.Message{other}, sameMessage), "Messages of another conversation = %+v, want its one", got)

	_, err = s.Messages(ctx, "c03", 0, 10)
	is(t, err, store.ErrNotFound, "Messages of a conversation that does not exist")
}

// testLimits checks that a list asked for fewer than one entry lists
// none, rather than all of them or a failure, and that a conversation
// that does not exist is still not found.
func testLimits(t *testing.T, s store.Store) {
	ctx := t.Context()
	must(t, s.CreateConversation(ctx, conversation("c01", "person-a")), "CreateConversation")
	for i := range 2 {
		_, err := s.Append(ctx, "c01", 0, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", strconv.Itoa(i))})
		must(t, err, "Append")
	}
	for _, limit := range []int{0, -1} {
		cs, err := s.Conversations(ctx, "person-a", "", limit)
		must(t, err, "Conversations")
		checkf(t, len(cs) == 0, "Conversations(limit %d) = %v, want none", limit, each(cs, conversationID))
		msgs, err := s.Messages(ctx, "c01", 0, limit)
		must(t, err, "Messages")
		checkf(t, len(msgs) == 0, "Messages(limit %d) = %v, want none", limit, each(msgs, seqOf))
		_, err = s.Messages(ctx, "c02", 0, limit)
		is(t, err, store.ErrNotFound, "Messages of a conversation that does not exist, limit "+strconv.Itoa(limit))
	}
}

// testWelcomes checks that welcomes list per device, oldest first,
// each with the conversation and the sequence number of the commit that
// filed it, and that a device deletes its own and no other's.
func testWelcomes(t *testing.T, s store.Store) {
	ctx := t.Context()
	c1, c2 := conversation("c01", "person-a"), conversation("c02", "person-a")
	must(t, s.CreateConversation(ctx, c1), "CreateConversation")
	must(t, s.CreateConversation(ctx, c2), "CreateConversation")
	welcomed(t, s, "person-b", "dev-b")

	a := store.Member{Person: "person-a", Device: "dev-a"}
	m1, err := s.Append(ctx, "c01", 0, store.Append{
		Message: msg(store.KindCommit, 0, "person-a", "dev-a", "add three devices"),
		State: commit(c1, 1, []string{"person-a", "person-b", "person-c"}, a,
			store.Member{Person: "person-b", Device: "dev-b", Since: 1}, store.Member{Person: "person-b", Device: "dev-c", Since: 1},
			store.Member{Person: "person-c", Device: "dev-b", Since: 1}),
		Welcomes: []store.Welcome{welcome("w-1", "person-b", "dev-b"), welcome("w-2", "person-b", "dev-c"), welcome("w-3", "person-c", "dev-b")},
	})
	must(t, err, "Append of a commit")
	m2, err := s.Append(ctx, "c02", 0, store.Append{
		Message:  msg(store.KindCommit, 0, "person-a", "dev-a", "add person-b's device"),
		State:    commit(c2, 1, []string{"person-a", "person-b"}, a, store.Member{Person: "person-b", Device: "dev-b", Since: 1}),
		Welcomes: []store.Welcome{welcome("w-4", "person-b", "dev-b")},
	})
	must(t, err, "Append of a commit to another conversation")

	welcomed(t, s, "person-b", "dev-b", "w-1", "w-4")
	welcomed(t, s, "person-b", "dev-c", "w-2")
	welcomed(t, s, "person-c", "dev-b", "w-3")
	ws, err := s.Welcomes(ctx, "person-b", "dev-b")
	must(t, err, "Welcomes")
	w1, w4 := welcome("w-1", "person-b", "dev-b"), welcome("w-4", "person-b", "dev-b")
	w1.Conversation, w1.Seq, w4.Conversation, w4.Seq = "c01", m1.Seq, "c02", m2.Seq
	checkf(t, slices.EqualFunc(ws, []store.Welcome{w1, w4}, sameWelcome), "Welcomes = %+v, want %+v", ws, []store.Welcome{w1, w4})

	must(t, s.DeleteWelcome(ctx, "person-b", "dev-b", "w-1"), "DeleteWelcome")
	welcomed(t, s, "person-b", "dev-b", "w-4")
	is(t, s.DeleteWelcome(ctx, "person-b", "dev-b", "w-1"), store.ErrNotFound, "DeleteWelcome a second time")
	is(t, s.DeleteWelcome(ctx, "person-b", "dev-c", "w-4"), store.ErrNotFound, "DeleteWelcome of another device's welcome")
	is(t, s.DeleteWelcome(ctx, "person-c", "dev-b", "w-4"), store.ErrNotFound, "DeleteWelcome of another person's welcome")
	is(t, s.DeleteWelcome(ctx, "person-b", "dev-b", "w-9"), store.ErrNotFound, "DeleteWelcome of a welcome never filed")
	welcomed(t, s, "person-b", "dev-b", "w-4")
	welcomed(t, s, "person-b", "dev-c", "w-2")
	welcomed(t, s, "person-c", "dev-b", "w-3")
}

// testDeleteMessagesBefore checks that the messages and welcomes stored
// before a time go, in every conversation, that those after stay, and
// that a deleted message's sequence number is not taken again. The store
// keeps its own clock, so the times compared are the ones it stamped.
func testDeleteMessagesBefore(t *testing.T, s store.Store) {
	ctx := t.Context()
	c1, c2 := conversation("c01", "person-a"), conversation("c02", "person-a")
	must(t, s.CreateConversation(ctx, c1), "CreateConversation")
	must(t, s.CreateConversation(ctx, c2), "CreateConversation")
	pair := []string{"person-a", "person-b"}
	a, b := store.Member{Person: "person-a", Device: "dev-a"}, store.Member{Person: "person-b", Device: "dev-b", Since: 1}

	old1, err := s.Append(ctx, "c01", 0, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", "old 1")})
	must(t, err, "Append")
	old2, err := s.Append(ctx, "c01", 0, store.Append{
		Message: msg(store.KindCommit, 0, "person-a", "dev-a", "old 2"), State: commit(c1, 1, pair, a, b),
		Welcomes: []store.Welcome{welcome("w-old", "person-b", "dev-b")},
	})
	must(t, err, "Append")
	old3, err := s.Append(ctx, "c02", 0, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", "old 3")})
	must(t, err, "Append")
	n, err := s.DeleteMessagesBefore(ctx, old1.Created)
	must(t, err, "DeleteMessagesBefore")
	checkf(t, n == 0, "DeleteMessagesBefore the time of the first message deleted %d, want 0", n)

	time.Sleep(20 * time.Millisecond)
	new1, err := s.Append(ctx, "c01", 1, store.Append{
		Message: msg(store.KindCommit, 1, "person-a", "dev-a", "new 1"), State: commit(c1, 2, pair, a, b),
		Welcomes: []store.Welcome{welcome("w-new", "person-b", "dev-b")},
	})
	must(t, err, "Append")
	new2, err := s.Append(ctx, "c02", 0, store.Append{Message: msg(store.KindApplication, 0, "person-a", "dev-a", "new 2")})
	must(t, err, "Append")
	ws, err := s.Welcomes(ctx, "person-b", "dev-b")
	must(t, err, "Welcomes")
	requiref(t, len(ws) == 2, "Welcomes = %v, want w-old and w-new", each(ws, welcomeID))
	last := slices.MaxFunc([]time.Time{old1.Created, old2.Created, old3.Created, ws[0].Created}, time.Time.Compare)
	first := slices.MinFunc([]time.Time{new1.Created, new2.Created, ws[1].Created}, time.Time.Compare)
	requiref(t, first.After(last), "the store stamped the later messages at %v, not after the earlier ones at %v", first, last)
	cut := last.Add(first.Sub(last) / 2)

	n, err = s.DeleteMessagesBefore(ctx, cut)
	must(t, err, "DeleteMessagesBefore")
	checkf(t, n == 3, "DeleteMessagesBefore deleted %d messages, want the 3 stored before", n)
	got, err := s.Messages(ctx, "c01", 0, 10)
	must(t, err, "Messages")
	checkf(t, slices.Equal(each(got, seqOf), []int64{new1.Seq}), "c01 keeps %v, want %d", each(got, seqOf), new1.Seq)
	got, err = s.Messages(ctx, "c02", 0, 10)
	must(t, err, "Messages")
	checkf(t, slices.Equal(each(got, seqOf), []int64{new2.Seq}), "c02 keeps %v, want %d", each(got, seqOf), new2.Seq)
	welcomed(t, s, "person-b", "dev-b", "w-new")

	n, err = s.DeleteMessagesBefore(ctx, cut)
	must(t, err, "DeleteMessagesBefore again")
	checkf(t, n == 0, "DeleteMessagesBefore again deleted %d, want 0", n)
	c, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation after its old messages went")
	m, err := s.Append(ctx, "c01", c.Version, store.Append{Message: msg(store.KindApplication, 2, "person-a", "dev-a", "after")})
	must(t, err, "Append")
	checkf(t, m.Seq == new1.Seq+1, "the next message has seq %d, want %d", m.Seq, new1.Seq+1)

	n, err = s.DeleteMessagesBefore(ctx, m.Created.Add(time.Hour))
	must(t, err, "DeleteMessagesBefore a time ahead of every message")
	checkf(t, n == 3, "DeleteMessagesBefore a time ahead deleted %d, want the 3 left", n)
	welcomed(t, s, "person-b", "dev-b")
}

// testSpans checks that a conversation keeps each device's spans as a
// commit leaves them, so a device reads the epochs it was a member for:
// from the commit that added it to the one that removed it, and again
// once added back.
func testSpans(t *testing.T, s store.Store) {
	ctx := t.Context()
	must(t, s.CreateConversation(ctx, conversation("c01", "person-a")), "CreateConversation")
	pair := []string{"person-a", "person-b"}
	a := store.Member{Person: "person-a", Device: "dev-a"}
	added := store.Member{Person: "person-b", Device: "dev-b", Since: 1}
	removed := store.Member{Person: "person-b", Device: "dev-b", Since: 1, Until: 3}
	again := store.Member{Person: "person-b", Device: "dev-b", Since: 5}
	var members []store.Member
	for _, step := range []struct {
		epoch   uint64
		members []store.Member
	}{
		{1, []store.Member{a, added}},
		{3, []store.Member{a, removed}},
		{5, []store.Member{a, removed, again}},
	} {
		c, err := s.Conversation(ctx, "c01")
		must(t, err, "Conversation")
		_, err = s.Append(ctx, "c01", c.Version, store.Append{
			Message: msg(store.KindCommit, c.Epoch, "person-a", "dev-a", "to epoch "+strconv.FormatUint(step.epoch, 10)),
			State:   commit(c, step.epoch, pair, step.members...),
		})
		must(t, err, "Append of a commit")
		members = step.members
	}
	got, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	checkf(t, sameMembers(got.Members, members), "Members = %+v, want %+v", got.Members, members)
	for _, q := range []struct {
		person, device string
		epoch          uint64
		want           bool
	}{
		{"person-a", "dev-a", 0, true},
		{"person-a", "dev-a", 6, true},
		{"person-b", "dev-b", 0, false},
		{"person-b", "dev-b", 1, true},
		{"person-b", "dev-b", 2, true},
		{"person-b", "dev-b", 3, false},
		{"person-b", "dev-b", 4, false},
		{"person-b", "dev-b", 5, true},
		{"person-b", "dev-b", 9, true},
		{"person-b", "dev-a", 1, false},
		{"person-a", "dev-b", 1, false},
	} {
		checkf(t, got.MayRead(q.person, q.device, q.epoch) == q.want, "MayRead(%s/%s, epoch %d) = %v, want %v", q.person, q.device, q.epoch, !q.want, q.want)
	}
	checkf(t, got.Leaf("person-a", "dev-a") && got.Leaf("person-b", "dev-b") && !got.Leaf("person-b", "dev-a"),
		"Leaf: person-a/dev-a %v, person-b/dev-b %v, person-b/dev-a %v; want true, true, false",
		got.Leaf("person-a", "dev-a"), got.Leaf("person-b", "dev-b"), got.Leaf("person-b", "dev-a"))
}

// testCopies checks that what a store is handed and what it hands back
// are the caller's own: a caller that changes either afterward, as one
// reusing its buffers does, changes nothing the store keeps.
func testCopies(t *testing.T, s store.Store) {
	ctx := t.Context()
	r := device("person-a", "dev-a")
	must(t, s.PutDevice(ctx, r, nil), "PutDevice")
	clear(r.SignatureKey)
	clear(r.EncryptionKey)
	clear(r.Vouch)
	rs, err := s.Devices(ctx, "person-a")
	must(t, err, "Devices")
	requiref(t, len(rs) == 1, "Devices = %v, want one", each(rs, recordID))
	clear(rs[0].SignatureKey)
	clear(rs[0].Possession)
	rs, err = s.Devices(ctx, "person-a")
	must(t, err, "Devices")
	checkf(t, slices.EqualFunc(rs, []messaging.DeviceRecord{device("person-a", "dev-a")}, sameRecord), "a record changed with a copy handed in or read out")

	v := revocation("person-a", "dev-b", "dev-c")
	must(t, s.AddRevocation(ctx, v, "", nil), "AddRevocation")
	clear(v.Key)
	clear(v.Keep[0])
	vs, err := s.Revocations(ctx, "person-a")
	must(t, err, "Revocations")
	requiref(t, len(vs) == 1 && len(vs[0].Keep) == 1, "Revocations = %v, want one that keeps one key", each(vs, revokedBy))
	clear(vs[0].Signature)
	clear(vs[0].Keep[0])
	vs, err = s.Revocations(ctx, "person-a")
	must(t, err, "Revocations")
	checkf(t, slices.EqualFunc(vs, []messaging.Revocation{revocation("person-a", "dev-b", "dev-c")}, sameRevocation), "a revocation changed with a copy handed in or read out")

	wrapped := fake("wrapped backup key", "person-a")
	must(t, s.PutRecovery(ctx, "person-a", wrapped), "PutRecovery")
	clear(wrapped)
	got, err := s.Recovery(ctx, "person-a")
	must(t, err, "Recovery")
	clear(got)
	got, err = s.Recovery(ctx, "person-a")
	must(t, err, "Recovery")
	checkf(t, bytes.Equal(got, fake("wrapped backup key", "person-a")), "the backup key changed with a copy handed in or read out: %q", got)

	sealed := fake("sealed backup key", "person-a", "dev-b")
	must(t, s.PutTransfer(ctx, "person-a", "dev-b", sealed), "PutTransfer")
	clear(sealed)
	got, err = s.TakeTransfer(ctx, "person-a", "dev-b")
	must(t, err, "TakeTransfer")
	checkf(t, bytes.Equal(got, fake("sealed backup key", "person-a", "dev-b")), "a transfer changed with the copy handed in: %q", got)

	kp := keyPackage("person-a", "dev-a", "last", true)
	must(t, s.AddKeyPackages(ctx, []store.KeyPackage{kp}), "AddKeyPackages")
	clear(kp.Data)
	claimed, err := s.ClaimKeyPackage(ctx, "person-a", "dev-a")
	must(t, err, "ClaimKeyPackage")
	clear(claimed.Data)
	claim(t, s, keyPackage("person-a", "dev-a", "last", true), "a last resort whose copies, handed in and out, were changed")

	c := conversation("c01", "person-a", "person-b")
	must(t, s.CreateConversation(ctx, c), "CreateConversation")
	clear(c.View)
	c.People[0], c.Owners[0], c.Members[0].Device = "person-x", "person-x", "dev-x"
	read, err := s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	clear(read.GroupInfo)
	read.People[1], read.Members[0].Person = "person-x", "person-x"
	read, err = s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	checkf(t, sameState(read, conversation("c01", "person-a", "person-b")), "a conversation changed with a copy handed in or read out: %+v", read)

	sent := msg(store.KindCommit, 0, "person-a", "dev-a", "add person-b's device")
	members := []store.Member{{Person: "person-a", Device: "dev-a"}, {Person: "person-b", Device: "dev-b", Since: 1}}
	state := commit(read, 1, []string{"person-a", "person-b"}, members...)
	w := welcome("w-1", "person-b", "dev-b")
	appended, err := s.Append(ctx, "c01", read.Version, store.Append{Message: sent, State: state, Welcomes: []store.Welcome{w}})
	must(t, err, "Append")
	clear(sent.Data)
	clear(state.View)
	clear(w.Data)
	clear(w.Notice)
	state.People[0], members[1].Device = "person-x", "dev-x"
	clear(appended.Data)
	msgs, err := s.Messages(ctx, "c01", 0, 10)
	must(t, err, "Messages")
	requiref(t, len(msgs) == 1, "Messages = %v, want one", each(msgs, seqOf))
	clear(msgs[0].Data)
	msgs, err = s.Messages(ctx, "c01", 0, 10)
	must(t, err, "Messages")
	wantMsg := msg(store.KindCommit, 0, "person-a", "dev-a", "add person-b's device")
	wantMsg.Conversation, wantMsg.Seq = "c01", 1
	checkf(t, slices.EqualFunc(msgs, []store.Message{wantMsg}, sameMessage), "a message changed with a copy handed in or read out: %+v", msgs)
	read, err = s.Conversation(ctx, "c01")
	must(t, err, "Conversation")
	wantState := commit(conversation("c01", "person-a", "person-b"), 1, []string{"person-a", "person-b"},
		store.Member{Person: "person-a", Device: "dev-a"}, store.Member{Person: "person-b", Device: "dev-b", Since: 1})
	checkf(t, sameState(read, *wantState), "a conversation changed with the state handed to Append: %+v", read)
	ws, err := s.Welcomes(ctx, "person-b", "dev-b")
	must(t, err, "Welcomes")
	requiref(t, len(ws) == 1, "Welcomes = %v, want one", each(ws, welcomeID))
	clear(ws[0].Data)
	clear(ws[0].Notice)
	ws, err = s.Welcomes(ctx, "person-b", "dev-b")
	must(t, err, "Welcomes")
	wantWelcome := welcome("w-1", "person-b", "dev-b")
	wantWelcome.Conversation, wantWelcome.Seq = "c01", 1
	checkf(t, slices.EqualFunc(ws, []store.Welcome{wantWelcome}, sameWelcome), "a welcome changed with a copy handed in or read out: %+v", ws)
}

// publish gives a device two one-time key packages, a last resort and a
// transfer.
func publish(t *testing.T, s store.Store, person, device string) {
	t.Helper()
	must(t, s.AddKeyPackages(t.Context(), []store.KeyPackage{
		keyPackage(person, device, "1", false), keyPackage(person, device, "2", false), keyPackage(person, device, "last", true),
	}), "AddKeyPackages")
	must(t, s.PutTransfer(t.Context(), person, device, fake("sealed backup key", person, device)), "PutTransfer")
}

// gone checks that a device has no key package and no transfer left.
func gone(t *testing.T, s store.Store, person, device string) {
	t.Helper()
	count(t, s, person, device, 0, false)
	_, err := s.ClaimKeyPackage(t.Context(), person, device)
	is(t, err, store.ErrNotFound, "ClaimKeyPackage for "+person+"/"+device)
	_, err = s.TakeTransfer(t.Context(), person, device)
	is(t, err, store.ErrNotFound, "TakeTransfer for "+person+"/"+device)
}

// count checks how many one-time key packages a device has and whether
// it has a last resort.
func count(t *testing.T, s store.Store, person, device string, n int, lastResort bool) {
	t.Helper()
	gotN, gotLast, err := s.CountKeyPackages(t.Context(), person, device)
	must(t, err, "CountKeyPackages")
	checkf(t, gotN == n && gotLast == lastResort, "%s/%s has %d one-time key packages and last resort %v, want %d and %v",
		person, device, gotN, gotLast, n, lastResort)
}

// claim checks that a claim of the package's device hands out that
// package.
func claim(t *testing.T, s store.Store, want store.KeyPackage, why string) {
	t.Helper()
	got, err := s.ClaimKeyPackage(t.Context(), want.Person, want.Device)
	must(t, err, "ClaimKeyPackage: "+why)
	checkf(t, sameKeyPackage(got, want), "ClaimKeyPackage = %s, want %s: %s", got.Ref, want.Ref, why)
}

// welcomed checks the ids of a device's welcomes, in order.
func welcomed(t *testing.T, s store.Store, person, device string, ids ...string) {
	t.Helper()
	ws, err := s.Welcomes(t.Context(), person, device)
	must(t, err, "Welcomes")
	checkf(t, slices.Equal(each(ws, welcomeID), ids), "Welcomes of %s/%s = %v, want %v", person, device, each(ws, welcomeID), ids)
}

// fake is an obviously fake value of a kind, which names whose it is.
func fake(what string, whose ...string) []byte {
	return []byte("fake " + what + " of " + strings.Join(whose, "/"))
}

// device is a device's directory record with fake keys and signatures.
func device(person, id string) messaging.DeviceRecord {
	return messaging.DeviceRecord{
		Person: person, ID: id, Kind: messaging.RecordDevice,
		SignatureKey: fake("signature key", person, id), EncryptionKey: fake("encryption key", person, id),
		Voucher: id, VoucherKey: fake("signature key", person, id),
		Vouch: fake("vouch", person, id), Possession: fake("possession", person, id),
	}
}

// recovery is the record of a person's recovery key: a device vouches
// for it, and it has no encryption key.
func recovery(person, id string, voucher messaging.DeviceRecord) messaging.DeviceRecord {
	r := device(person, id)
	r.Kind, r.EncryptionKey = messaging.RecordRecovery, nil
	r.Voucher, r.VoucherKey = voucher.ID, bytes.Clone(voucher.SignatureKey)
	return r
}

// revocation is a person's revocation of a record's key, signed by that
// record, keeping the keys of the records named.
func revocation(person, id string, keep ...string) messaging.Revocation {
	v := messaging.Revocation{Person: person, Key: fake("signature key", person, id), By: id, Signature: fake("revocation signature", person, id)}
	for _, k := range keep {
		v.Keep = append(v.Keep, fake("signature key", person, k))
	}
	return v
}

// keyPackage is a device's key package, whose hex ref names the device
// and the label.
func keyPackage(person, device, label string, lastResort bool) store.KeyPackage {
	return store.KeyPackage{
		Ref: fmt.Sprintf("%x", person+"/"+device+"/"+label), Person: person, Device: device,
		Data: fake("key package "+label, person, device), LastResort: lastResort,
	}
}

// conversation is a group of the people given at epoch 0 that the
// assistant reads along in, owned by its first person, whose dev-a is
// its one member.
func conversation(id string, people ...string) store.Conversation {
	return store.Conversation{
		ID: id, Kind: messaging.KindGroup, Level: messaging.LevelReadsAlong,
		People: people, Owners: []string{people[0]},
		View: fake("view at epoch 0", id), GroupInfo: fake("group info at epoch 0", id),
		Members: []store.Member{{Person: people[0], Device: "dev-a"}},
	}
}

// proposed is the state a proposal leaves: the view moves on, the epoch
// stays.
func proposed(c store.Conversation, label string) *store.Conversation {
	c.View = fake("view with proposal "+label, c.ID)
	return &c
}

// commit is the state a commit leaves: the conversation at the epoch,
// with the people and members given, and a view and group info of that
// epoch.
func commit(c store.Conversation, epoch uint64, people []string, members ...store.Member) *store.Conversation {
	c.Epoch, c.People, c.Members = epoch, people, members
	c.View = fake(fmt.Sprintf("view at epoch %d", epoch), c.ID)
	c.GroupInfo = fake(fmt.Sprintf("group info at epoch %d", epoch), c.ID)
	return &c
}

// msg is a message of a device's at an epoch, whose fake ciphertext names
// it. A proposal of the service's own has no person and no device.
func msg(kind store.MessageKind, epoch uint64, person, device, text string) store.Message {
	return store.Message{Epoch: epoch, Kind: kind, Person: person, Device: device, Data: fake(string(kind)+" "+text, person, device)}
}

// welcome is a Welcome for a device, with a Seq the store is to set.
func welcome(id, person, device string) store.Welcome {
	return store.Welcome{ID: id, Person: person, Device: device, Seq: 99, Data: fake("welcome "+id, person, device), Notice: fake("history notice "+id, person, device)}
}

func sameRecord(a, b messaging.DeviceRecord) bool {
	return a.Person == b.Person && a.ID == b.ID && a.Kind == b.Kind && bytes.Equal(a.SignatureKey, b.SignatureKey) &&
		bytes.Equal(a.EncryptionKey, b.EncryptionKey) && a.Voucher == b.Voucher && bytes.Equal(a.VoucherKey, b.VoucherKey) &&
		bytes.Equal(a.Vouch, b.Vouch) && bytes.Equal(a.Possession, b.Possession)
}

func sameRevocation(a, b messaging.Revocation) bool {
	return a.Person == b.Person && bytes.Equal(a.Key, b.Key) && slices.EqualFunc(a.Keep, b.Keep, bytes.Equal) &&
		a.By == b.By && bytes.Equal(a.Signature, b.Signature)
}

func sameKeyPackage(a, b store.KeyPackage) bool {
	return a.Ref == b.Ref && a.Person == b.Person && a.Device == b.Device && bytes.Equal(a.Data, b.Data) && a.LastResort == b.LastResort
}

// sameState reports whether two conversations hold one state: every
// field a caller gives. The sequence number, the version and the times
// are the store's, and are checked apart.
func sameState(a, b store.Conversation) bool {
	return a.ID == b.ID && a.Kind == b.Kind && a.Level == b.Level && slices.Equal(a.People, b.People) &&
		slices.Equal(a.Owners, b.Owners) && a.Epoch == b.Epoch && bytes.Equal(a.View, b.View) &&
		bytes.Equal(a.GroupInfo, b.GroupInfo) && sameMembers(a.Members, b.Members)
}

// sameMembers compares two sets of spans. The contract names no order
// for them.
func sameMembers(a, b []store.Member) bool {
	return slices.Equal(sortedMembers(a), sortedMembers(b))
}

func sortedMembers(ms []store.Member) []store.Member {
	return slices.SortedFunc(slices.Values(ms), func(x, y store.Member) int {
		return cmp.Or(cmp.Compare(x.Person, y.Person), cmp.Compare(x.Device, y.Device), cmp.Compare(x.Since, y.Since), cmp.Compare(x.Until, y.Until))
	})
}

// sameMessage compares two messages but for the time, which is the
// store's.
func sameMessage(a, b store.Message) bool {
	return a.Conversation == b.Conversation && a.Seq == b.Seq && a.Epoch == b.Epoch && a.Kind == b.Kind &&
		bytes.Equal(a.Data, b.Data) && a.Person == b.Person && a.Device == b.Device
}

// sameWelcome compares two welcomes but for the time, which is the
// store's.
func sameWelcome(a, b store.Welcome) bool {
	return a.ID == b.ID && a.Person == b.Person && a.Device == b.Device && a.Conversation == b.Conversation &&
		a.Seq == b.Seq && bytes.Equal(a.Data, b.Data) && bytes.Equal(a.Notice, b.Notice)
}

// each is f of every element, for a failure message.
func each[T, K any](xs []T, f func(T) K) []K {
	out := make([]K, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}

func recordID(r messaging.DeviceRecord) string   { return r.ID }
func revokedBy(v messaging.Revocation) string    { return v.By }
func conversationID(c store.Conversation) string { return c.ID }
func seqOf(m store.Message) int64                { return m.Seq }
func welcomeID(w store.Welcome) string           { return w.ID }

// The four ways a check fails. Every failure of the suite goes through
// one of them, so a passing run leaves only their failure lines unrun.

// requiref stops the test when a condition the rest of it builds on does
// not hold.
func requiref(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

// checkf reports a condition that does not hold and lets the test go on.
func checkf(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Errorf(format, args...)
	}
}

// must stops the test on an error.
func must(t *testing.T, err error, what string) {
	t.Helper()
	requiref(t, err == nil, "%s: %v", what, err)
}

// is reports an error that is not the one the contract names.
func is(t *testing.T, err, want error, what string) {
	t.Helper()
	checkf(t, errors.Is(err, want), "%s: err = %v, want %v", what, err, want)
}
