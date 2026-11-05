// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/internal/store"
)

var benchBase = time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)

// benchBlob is n deterministic bytes, standing for an MLS message or a
// sealed backup record.
func benchBlob(n int, salt int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + salt*17 + 7) % 251)
	}
	return b
}

func benchMessageList(count, size int) MessageList {
	l := MessageList{Messages: make([]Message, count), Next: int64(count)}
	for i := range l.Messages {
		l.Messages[i] = Message{
			Seq: int64(i + 1), Epoch: uint64(3 + i/50), Kind: store.KindApplication,
			Message: benchBlob(size, i),
			Person:  fmt.Sprintf("0b6f1c52-7d1e-4c3a-9a10-%012d", i%7),
			Device:  fmt.Sprintf("d-%08x", i%11),
			Created: benchBase.Add(time.Duration(i) * time.Second),
		}
	}
	return l
}

func benchWriteJSON(b *testing.B, v any) {
	b.Helper()
	log := slog.New(slog.DiscardHandler)
	enc, err := json.Marshal(v)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(enc) + 1))
	for b.Loop() {
		rec := httptest.NewRecorder()
		writeJSON(rec, log, http.StatusOK, v)
		if rec.Code != http.StatusOK {
			b.Fatalf("status %d", rec.Code)
		}
	}
}

func benchDecode(b *testing.B, body []byte, mk func() any) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		r, err := http.NewRequest(http.MethodPost, Prefix+"/x", bytes.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		if err := decode(r, mk()); err != nil {
			b.Fatal(err)
		}
	}
}

// The read of a conversation's log: the response a device polls for.
func BenchmarkJSONMessageListEncode(b *testing.B) {
	for _, c := range []struct {
		name        string
		count, size int
	}{{"small", 1, 300}, {"medium", 12, 600}, {"large", 250, 600}} {
		b.Run(c.name, func(b *testing.B) { benchWriteJSON(b, benchMessageList(c.count, c.size)) })
	}
}

// The list of conversations a device syncs on start.
func BenchmarkJSONConversationListEncode(b *testing.B) {
	for _, c := range []struct {
		name string
		n    int
	}{{"small", 2}, {"medium", 40}, {"large", 800}} {
		l := ConversationList{Conversations: make([]Conversation, c.n), Next: "c-cursor-0001"}
		for i := range l.Conversations {
			l.Conversations[i] = Conversation{
				ID: fmt.Sprintf("conv-%016x", i), Kind: messaging.KindGroup, Level: messaging.LevelReadsAlong,
				People: []string{"0b6f1c52-7d1e-4c3a-9a10-000000000001", "0b6f1c52-7d1e-4c3a-9a10-000000000002", "0b6f1c52-7d1e-4c3a-9a10-000000000003"},
				Owners: []string{"0b6f1c52-7d1e-4c3a-9a10-000000000001"},
				Epoch:  uint64(i % 9), Seq: int64(i * 13), Created: benchBase, Updated: benchBase.Add(time.Hour),
			}
		}
		b.Run(c.name, func(b *testing.B) { benchWriteJSON(b, l) })
	}
}

// The welcomes a device collects when it joins groups.
func BenchmarkJSONWelcomeListEncode(b *testing.B) {
	l := WelcomeList{Welcomes: make([]Welcome, 8)}
	for i := range l.Welcomes {
		l.Welcomes[i] = Welcome{ID: fmt.Sprintf("w-%08x", i), Conversation: fmt.Sprintf("conv-%016x", i), Seq: int64(i + 1),
			Welcome: benchBlob(1500, i), Notice: benchBlob(200, i), Created: benchBase}
	}
	benchWriteJSON(b, l)
}

// The request body of a send: one MLS message, sometimes with a welcome and
// group info.
func BenchmarkJSONSendBodyDecode(b *testing.B) {
	for _, c := range []struct {
		name string
		body SendBody
	}{
		{"small", SendBody{Message: benchBlob(300, 1)}},
		{"medium", SendBody{Message: benchBlob(2000, 1), Welcome: benchBlob(3000, 2), GroupInfo: benchBlob(2500, 3)}},
		{"large", SendBody{Message: benchBlob(60000, 1), Welcome: benchBlob(60000, 2), GroupInfo: benchBlob(60000, 3)}},
	} {
		body, err := json.Marshal(c.body)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(c.name, func(b *testing.B) { benchDecode(b, body, func() any { return new(SendBody) }) })
	}
}

// The request body of a history backup upload.
func BenchmarkJSONBackupPutDecode(b *testing.B) {
	for _, c := range []struct {
		name        string
		count, size int
	}{{"small", 1, 250}, {"medium", 20, 350}, {"large", 400, 350}} {
		put := BackupPut{Records: make([]BackupRecord, c.count)}
		for i := range put.Records {
			put.Records[i] = BackupRecord{ID: fmt.Sprintf("%064x", i), Sealed: benchBlob(c.size, i)}
		}
		body, err := json.Marshal(put)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(c.name, func(b *testing.B) { benchDecode(b, body, func() any { return new(BackupPut) }) })
	}
}

// The body of a create call.
func BenchmarkJSONCreateBodyDecode(b *testing.B) {
	body, err := json.Marshal(CreateBody{ID: "conv-0000000000000001", GroupInfo: benchBlob(2500, 1)})
	if err != nil {
		b.Fatal(err)
	}
	benchDecode(b, body, func() any { return new(CreateBody) })
}
