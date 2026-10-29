// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"testing"

	"latere.ai/x/sermo/internal/store"
)

// TestConversationSpans checks the reads a device's spans allow, on a
// conversation built by hand: a span holds its first epoch and not the
// one its removal starts, an open span holds every later epoch, and a
// device added again has a span for each time.
func TestConversationSpans(t *testing.T) {
	c := store.Conversation{
		People: []string{"person-a", "person-b"},
		Members: []store.Member{
			{Person: "person-a", Device: "dev-a"},
			{Person: "person-b", Device: "dev-b", Since: 2, Until: 4},
			{Person: "person-b", Device: "dev-b", Since: 7},
			{Person: "person-b", Device: "dev-c", Since: 1, Until: 3},
		},
	}
	for _, q := range []struct {
		person, device string
		epoch          uint64
		want           bool
	}{
		{"person-a", "dev-a", 0, true},
		{"person-a", "dev-a", 1 << 40, true},
		{"person-b", "dev-b", 1, false},
		{"person-b", "dev-b", 2, true},
		{"person-b", "dev-b", 3, true},
		{"person-b", "dev-b", 4, false},
		{"person-b", "dev-b", 6, false},
		{"person-b", "dev-b", 7, true},
		{"person-b", "dev-c", 2, true},
		{"person-b", "dev-c", 3, false},
		{"person-a", "dev-b", 2, false},
		{"person-c", "dev-a", 0, false},
	} {
		if got := c.MayRead(q.person, q.device, q.epoch); got != q.want {
			t.Errorf("MayRead(%s/%s, epoch %d) = %v, want %v", q.person, q.device, q.epoch, got, q.want)
		}
	}
	for _, q := range []struct {
		person, device string
		want           bool
	}{
		{"person-a", "dev-a", true},
		{"person-b", "dev-b", true},
		{"person-b", "dev-c", false},
		{"person-a", "dev-c", false},
	} {
		if got := c.Leaf(q.person, q.device); got != q.want {
			t.Errorf("Leaf(%s/%s) = %v, want %v", q.person, q.device, got, q.want)
		}
	}
	if !c.Has("person-b") || c.Has("person-c") {
		t.Errorf("Has: person-b %v, person-c %v; want true, false", c.Has("person-b"), c.Has("person-c"))
	}
}
