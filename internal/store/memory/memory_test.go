// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"testing"
	"time"

	"latere.ai/x/sermo/internal/store"
	"latere.ai/x/sermo/internal/store/memory"
	"latere.ai/x/sermo/internal/store/storetest"
)

// TestContract runs the store contract against the store in memory, on
// the wall clock.
func TestContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return memory.New(nil) })
}

// TestDeleteMessagesBeforeIsStrict checks, on a clock the test moves,
// that a message stored at the very time given is not before it and
// stays, and that the clock given to New is the one messages and
// welcomes are stamped with.
func TestDeleteMessagesBeforeIsStrict(t *testing.T) {
	ctx := t.Context()
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	s := memory.New(func() time.Time { return at })
	c := store.Conversation{ID: "c01", People: []string{"person-a"}, Members: []store.Member{{Person: "person-a", Device: "dev-a"}}}
	if err := s.CreateConversation(ctx, c); err != nil {
		t.Fatal(err)
	}
	m, err := s.Append(ctx, "c01", 0, store.Append{
		Message:  store.Message{Kind: store.KindCommit, Person: "person-a", Device: "dev-a", Data: []byte("fake commit")},
		State:    &c,
		Welcomes: []store.Welcome{{ID: "w-1", Person: "person-b", Device: "dev-b", Data: []byte("fake welcome")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Created.Equal(at) {
		t.Errorf("the message was stamped %v, want the store's clock, %v", m.Created, at)
	}
	n, err := s.DeleteMessagesBefore(ctx, at)
	if err != nil || n != 0 {
		t.Errorf("DeleteMessagesBefore its own time = %d, %v; want 0 deleted", n, err)
	}
	if ws, err := s.Welcomes(ctx, "person-b", "dev-b"); err != nil || len(ws) != 1 || !ws[0].Created.Equal(at) {
		t.Errorf("Welcomes = %+v, %v; want the one stamped %v, kept", ws, err, at)
	}
	n, err = s.DeleteMessagesBefore(ctx, at.Add(time.Nanosecond))
	if err != nil || n != 1 {
		t.Errorf("DeleteMessagesBefore a nanosecond after = %d, %v; want 1 deleted", n, err)
	}
	if ws, err := s.Welcomes(ctx, "person-b", "dev-b"); err != nil || len(ws) != 0 {
		t.Errorf("Welcomes = %+v, %v; want none left", ws, err)
	}
}

// TestKeyPackageKeepsItsTime checks that a key package published with a
// time keeps it, and one published without is stamped by the clock.
func TestKeyPackageKeepsItsTime(t *testing.T) {
	ctx := t.Context()
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	given := at.Add(-time.Hour)
	s := memory.New(func() time.Time { return at })
	if err := s.AddKeyPackages(ctx, []store.KeyPackage{
		{Ref: "01", Person: "person-a", Device: "dev-a", Data: []byte("fake key package 1"), Created: given},
		{Ref: "02", Person: "person-a", Device: "dev-a", Data: []byte("fake key package 2")},
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []time.Time{given, at} {
		kp, err := s.ClaimKeyPackage(ctx, "person-a", "dev-a")
		if err != nil {
			t.Fatal(err)
		}
		if !kp.Created.Equal(want) {
			t.Errorf("key package %s was created %v, want %v", kp.Ref, kp.Created, want)
		}
	}
}
