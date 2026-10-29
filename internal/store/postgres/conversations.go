// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"latere.ai/x/sermo/internal/store"
)

const (
	conversationColumns = `id, kind, level, people, owners, epoch, seq, version, view, group_info, members, created, updated`

	// createConversation starts a conversation at seq 0 and version 0, and
	// leaves one whose id is taken as it is.
	createConversation = `
insert into conversations (id, kind, level, people, owners, epoch, seq, version, view, group_info, members, created, updated)
values ($1, $2, $3, $4, $5, $6, 0, 0, $7, $8, $9::jsonb, $10, $10)
on conflict (id) do nothing`
	getConversation   = `select ` + conversationColumns + ` from conversations where id = $1`
	listConversations = `
select ` + conversationColumns + ` from conversations
where people @> array[$1::text] and id > $2 order by id limit $3`
	conversationExists = `select exists (select 1 from conversations where id = $1)`

	// advance and advanceState take the next sequence number of a
	// conversation still at the version read. Under read committed, an
	// update that waited on another append's row lock reads the row that
	// append committed before it decides, so of two appends from one
	// version, the second sees a state the first changed and updates
	// nothing, and sees a message the first added and numbers after it.
	advance = `
update conversations set seq = seq + 1, updated = $3
where id = $1 and version = $2 returning seq`
	advanceState = `
update conversations set seq = seq + 1, version = version + 1, updated = $3,
    kind = $4, level = $5, people = $6, owners = $7, epoch = $8, view = $9, group_info = $10, members = $11::jsonb
where id = $1 and version = $2 returning seq`
	addMessage = `
insert into messages (conversation, seq, epoch, kind, data, person, device, created)
values ($1, $2, $3, $4, $5, $6, $7, $8)`
	addWelcome = `
insert into welcomes (id, person, device, conversation, seq, data, notice, created)
values ($1, $2, $3, $4, $5, $6, $7, $8)`

	listMessages = `
select conversation, seq, epoch, kind, data, person, device, created
from messages where conversation = $1 and seq > $2 order by seq limit $3`
	listWelcomes = `
select id, person, device, conversation, seq, data, notice, created
from welcomes where person = $1 and device = $2 order by ord`
	// deleteWelcome deletes the first welcome filed under the id, as the
	// store in memory does.
	deleteWelcome = `
delete from welcomes where ord = (
    select ord from welcomes where person = $1 and device = $2 and id = $3 order by ord limit 1)`
	deleteMessagesBefore = `delete from messages where created < $1`
	deleteWelcomesBefore = `delete from welcomes where created < $1`
)

// span is a member as the members column holds it. Its own type keeps
// the column's format apart from the Go names of store.Member.
type span struct {
	Person string `json:"person"`
	Device string `json:"device"`
	Since  uint64 `json:"since"`
	Until  uint64 `json:"until"`
}

// encodeMembers is the members column of a state, as a string: in the
// query mode a transaction pooler needs, a byte slice reaches a jsonb
// parameter as a bytea literal, which the column refuses.
func encodeMembers(ms []store.Member) (string, error) {
	spans := make([]span, len(ms))
	for i, m := range ms {
		spans[i] = span(m)
	}
	b, err := json.Marshal(spans)
	if err != nil {
		return "", fmt.Errorf("encoding the members: %w", err)
	}
	return string(b), nil
}

func decodeMembers(b []byte) ([]store.Member, error) {
	var spans []span
	if err := json.Unmarshal(b, &spans); err != nil {
		return nil, fmt.Errorf("decoding the members: %w", err)
	}
	var ms []store.Member
	for _, sp := range spans {
		ms = append(ms, store.Member(sp))
	}
	return ms, nil
}

func scanConversation(row pgx.Row) (store.Conversation, error) {
	var (
		c       store.Conversation
		members []byte
	)
	if err := row.Scan(&c.ID, &c.Kind, &c.Level, &c.People, &c.Owners, &c.Epoch, &c.Seq, &c.Version,
		&c.View, &c.GroupInfo, &members, &c.Created, &c.Updated); err != nil {
		return store.Conversation{}, err
	}
	ms, err := decodeMembers(members)
	if err != nil {
		return store.Conversation{}, err
	}
	c.Members = ms
	return c, nil
}

// CreateConversation stores a new conversation.
func (s *Store) CreateConversation(ctx context.Context, c store.Conversation) error {
	members, err := encodeMembers(c.Members)
	if err != nil {
		return fail("creating a conversation", err)
	}
	tag, err := s.pool.Exec(ctx, createConversation, c.ID, c.Kind, c.Level, orEmpty(c.People), orEmpty(c.Owners),
		c.Epoch, c.View, c.GroupInfo, members, s.clock())
	if err != nil {
		return fail("creating a conversation", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrExists
	}
	return nil
}

// Conversation reads a conversation.
func (s *Store) Conversation(ctx context.Context, id string) (store.Conversation, error) {
	c, err := scanConversation(s.pool.QueryRow(ctx, getConversation, id))
	if err != nil {
		return store.Conversation{}, fail("reading a conversation", notFound(err))
	}
	return c, nil
}

// Conversations lists a person's conversations by id.
func (s *Store) Conversations(ctx context.Context, person, after string, limit int) ([]store.Conversation, error) {
	if limit < 1 {
		return nil, nil
	}
	out, err := list(ctx, s, listConversations, []any{person, after, limit}, func(row pgx.CollectableRow) (store.Conversation, error) {
		return scanConversation(row)
	})
	if err != nil {
		return nil, fail("listing conversations", err)
	}
	return out, nil
}

// Append appends a message, in one transaction with the state it carries
// and the welcomes it files.
func (s *Store) Append(ctx context.Context, id string, version int64, a store.Append) (store.Message, error) {
	now := s.clock()
	m := a.Message
	m.Conversation, m.Created = id, now
	var members string
	if a.State != nil {
		var err error
		if members, err = encodeMembers(a.State.Members); err != nil {
			return store.Message{}, fail("appending a message", err)
		}
	}
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var row pgx.Row
		if st := a.State; st != nil {
			row = tx.QueryRow(ctx, advanceState, id, version, now, st.Kind, st.Level, orEmpty(st.People), orEmpty(st.Owners),
				st.Epoch, st.View, st.GroupInfo, members)
		} else {
			row = tx.QueryRow(ctx, advance, id, version, now)
		}
		if err := row.Scan(&m.Seq); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return missing(ctx, tx, id)
			}
			return err
		}
		b := &pgx.Batch{}
		b.Queue(addMessage, id, m.Seq, m.Epoch, string(m.Kind), m.Data, m.Person, m.Device, now)
		for _, w := range a.Welcomes {
			b.Queue(addWelcome, w.ID, w.Person, w.Device, id, m.Seq, w.Data, w.Notice, now)
		}
		return tx.SendBatch(ctx, b).Close()
	})
	if err != nil {
		return store.Message{}, fail("appending a message", err)
	}
	return m, nil
}

// missing is why an append updated no conversation: there is none of the
// id, or it is no longer at the version read.
func missing(ctx context.Context, q pgx.Tx, id string) error {
	var exists bool
	if err := q.QueryRow(ctx, conversationExists, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return store.ErrConflict
	}
	return store.ErrNotFound
}

// Messages lists messages after a sequence number.
func (s *Store) Messages(ctx context.Context, id string, after int64, limit int) ([]store.Message, error) {
	var out []store.Message
	if limit >= 1 {
		var err error
		out, err = list(ctx, s, listMessages, []any{id, after, limit}, func(row pgx.CollectableRow) (store.Message, error) {
			var m store.Message
			err := row.Scan(&m.Conversation, &m.Seq, &m.Epoch, &m.Kind, &m.Data, &m.Person, &m.Device, &m.Created)
			return m, err
		})
		if err != nil {
			return nil, fail("listing messages", err)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	// No message is either a log with none after the number or no
	// conversation at all.
	var exists bool
	if err := s.pool.QueryRow(ctx, conversationExists, id).Scan(&exists); err != nil {
		return nil, fail("listing messages", err)
	}
	if !exists {
		return nil, store.ErrNotFound
	}
	return nil, nil
}

// Welcomes lists a device's welcomes in the order they were filed.
func (s *Store) Welcomes(ctx context.Context, person, device string) ([]store.Welcome, error) {
	out, err := list(ctx, s, listWelcomes, []any{person, device}, func(row pgx.CollectableRow) (store.Welcome, error) {
		var w store.Welcome
		err := row.Scan(&w.ID, &w.Person, &w.Device, &w.Conversation, &w.Seq, &w.Data, &w.Notice, &w.Created)
		return w, err
	})
	if err != nil {
		return nil, fail("listing welcomes", err)
	}
	return out, nil
}

// DeleteWelcome deletes a device's welcome.
func (s *Store) DeleteWelcome(ctx context.Context, person, device, id string) error {
	tag, err := s.pool.Exec(ctx, deleteWelcome, person, device, id)
	if err != nil {
		return fail("deleting a welcome", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteMessagesBefore deletes old messages and welcomes, in one
// transaction.
func (s *Store) DeleteMessagesBefore(ctx context.Context, before time.Time) (int, error) {
	// A stored time is a whole microsecond, so one is before the time
	// given exactly when it is before that time rounded up to the next.
	cut := micro(before)
	if cut.Before(before) {
		cut = cut.Add(time.Microsecond)
	}
	var n int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, deleteMessagesBefore, cut)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		_, err = tx.Exec(ctx, deleteWelcomesBefore, cut)
		return err
	})
	if err != nil {
		return 0, fail("deleting old messages", err)
	}
	return int(n), nil
}
