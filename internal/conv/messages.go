// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package conv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"latere.ai/x/sdk-go/messaging"
	"latere.ai/x/sdk-go/mls"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/apierr"
	"latere.ai/x/sermo/internal/store"
)

// Send is one MLS message a device sends to a conversation: a commit
// with the group info of the epoch it starts and, when it adds a leaf,
// its Welcome.
type Send struct {
	Message   []byte
	Welcome   []byte
	GroupInfo []byte
}

// Sent is what a send appended.
type Sent struct {
	Seq   int64
	Epoch uint64
	Kind  store.MessageKind
}

// Send checks a message against the group's public state and the rules,
// asks the authorizer, and appends it, one commit per epoch.
func (s *Service) Send(ctx context.Context, w Who, id string, in Send) (*Sent, error) {
	if len(in.Message) == 0 {
		return nil, apierr.New(apierr.CodeInvalid, "the message is empty")
	}
	if len(in.Message) > MaxMessageBytes {
		return nil, apierr.New(apierr.CodeTooLarge, fmt.Sprintf("a message is at most %d bytes", MaxMessageBytes))
	}
	info, err := mls.PeekMessage(in.Message)
	if err != nil {
		return nil, apierr.Wrap(apierr.CodeInvalid, err)
	}
	if !bytes.Equal(info.GroupID, messaging.GroupID(id)) {
		return nil, apierr.New(apierr.CodeInvalid, "the message is for another group")
	}
	// A commit whose epoch another commit took while this one was checked
	// is checked again against the new epoch, where it fails as taken.
	for range 3 {
		c, err := s.conversation(ctx, id)
		if err != nil {
			return nil, err
		}
		a, err := s.check(ctx, w, &c, info, in)
		if err != nil {
			return nil, err
		}
		m, err := s.store.Append(ctx, id, c.Version, *a)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			return nil, err
		}
		s.hub.wake(id)
		return &Sent{Seq: m.Seq, Epoch: m.Epoch, Kind: m.Kind}, nil
	}
	return nil, apierr.New(apierr.CodeEpochTaken, "the conversation kept changing")
}

func (s *Service) check(ctx context.Context, w Who, c *store.Conversation, info *mls.MessageInfo, in Send) (*store.Append, error) {
	switch {
	case !c.Has(w.Person): // no one else sends anything, so no one else learns how a message fares
		return nil, apierr.New(apierr.CodeForbidden, "the caller is not one of the conversation's people")
	case info.Epoch < c.Epoch && info.WireFormat == mls.WireFormatPrivateMessage:
		return nil, apierr.New(apierr.CodeWrongEpoch, fmt.Sprintf("the conversation is at epoch %d", c.Epoch))
	case info.Epoch < c.Epoch:
		return nil, apierr.New(apierr.CodeEpochTaken, fmt.Sprintf("the conversation is at epoch %d", c.Epoch))
	case info.Epoch > c.Epoch:
		return nil, apierr.New(apierr.CodeInvalid, fmt.Sprintf("the conversation is at epoch %d", c.Epoch))
	}
	msg := store.Message{Epoch: info.Epoch, Person: w.Person, Device: w.Device, Data: in.Message}
	if info.WireFormat == mls.WireFormatPrivateMessage {
		if info.Kind != mls.MessageApplication {
			return nil, apierr.New(apierr.CodeRefused, "handshake messages are sent in the clear")
		}
		if !c.Leaf(w.Person, w.Device) {
			return nil, apierr.New(apierr.CodeForbidden, "the device is not in the conversation's group")
		}
		if err := s.ask(ctx, w, authorizer.ActionConversationSend, c.ID, facts(c, map[string]any{authorizer.FieldSize: len(in.Message)})); err != nil {
			return nil, err
		}
		msg.Kind = store.KindApplication
		return &store.Append{Message: msg}, nil
	}
	if info.WireFormat != mls.WireFormatPublicMessage {
		return nil, apierr.New(apierr.CodeInvalid, "a conversation's message is a public or private message")
	}
	policy := s.policy(ctx)
	view, err := mls.UnmarshalPublicGroup(c.View, policy.Config())
	if err != nil {
		return nil, err
	}
	m, err := view.Process(in.Message)
	if err != nil {
		return nil, apierr.Wrap(apierr.CodeRefused, err)
	}
	if err := s.sentBy(ctx, m.Sender, w); err != nil {
		return nil, err
	}
	switch m.Kind {
	case mls.MessageProposal:
		return s.checkProposal(ctx, w, c, view, m, msg)
	case mls.MessageCommit:
		return s.checkCommit(ctx, w, c, view, m, msg, in)
	}
	return nil, apierr.New(apierr.CodeRefused, "an application message is encrypted")
}

// sentBy checks that a message's sender is the calling device: its
// leaf, or for a device joining on its own the leaf it joins with, with
// the device's credential and the key of its record.
func (s *Service) sentBy(ctx context.Context, sender mls.Sender, w Who) error {
	refused := apierr.New(apierr.CodeRefused, "the message's sender is not the calling device")
	if sender.Kind != mls.SenderMember && sender.Kind != mls.SenderNewMember {
		return refused
	}
	if string(sender.Credential.Identity) != leafOf(w) {
		return refused
	}
	d, err := s.directory(ctx, w.Person)
	if err != nil {
		return err
	}
	rec, ok := d.Device(w.Device)
	if !ok || !bytes.Equal(rec.SignatureKey, sender.SignatureKey) {
		return refused
	}
	return nil
}

func (s *Service) checkProposal(ctx context.Context, w Who, c *store.Conversation, view *mls.PublicGroup, m *mls.Message, msg store.Message) (*store.Append, error) {
	if err := s.policy(ctx).CheckProposal(view, *m.Proposal); err != nil {
		return nil, apierr.Wrap(apierr.CodeRefused, err)
	}
	action := authorizer.ActionConversationCommit
	if m.Proposal.Kind == mls.ProposalRemove {
		if target, ok := memberAt(view, m.Proposal.Leaf); ok {
			if id, err := messaging.ParseCredential(target.Credential); err == nil && id.Person == w.Person {
				action = authorizer.ActionConversationLeave
			}
		}
	}
	fields := map[string]any{}
	if action == authorizer.ActionConversationCommit {
		fields[authorizer.FieldChanges] = []string{proposalChange(m.Proposal.Kind)}
	}
	if err := s.ask(ctx, w, action, c.ID, facts(c, fields)); err != nil {
		return nil, err
	}
	next := *c
	var err error
	if next.View, err = view.MarshalBinary(); err != nil {
		return nil, err
	}
	msg.Kind = store.KindProposal
	return &store.Append{Message: msg, State: &next}, nil
}

func proposalChange(k mls.ProposalKind) string {
	switch k {
	case mls.ProposalAdd:
		return authorizer.ChangeAddPeople
	case mls.ProposalRemove:
		return authorizer.ChangeRemovePeople
	case mls.ProposalGroupContextExtensions:
		return authorizer.ChangeOwners
	}
	return authorizer.ChangeDevices
}

func memberAt(view *mls.PublicGroup, leaf uint32) (mls.Member, bool) {
	for _, m := range view.Members() {
		if m.Leaf == leaf {
			return m, true
		}
	}
	return mls.Member{}, false
}

func (s *Service) checkCommit(ctx context.Context, w Who, c *store.Conversation, view *mls.PublicGroup, m *mls.Message, msg store.Message, in Send) (*store.Append, error) {
	changes := m.Commit.Changes()
	change, err := s.policy(ctx).CheckCommit(view, changes)
	if err != nil {
		if errors.Is(err, messaging.ErrRefused) {
			return nil, apierr.Wrap(apierr.CodeRefused, err)
		}
		return nil, err
	}
	if changes.ReInit {
		return nil, apierr.New(apierr.CodeRefused, "a conversation is not reinitialized")
	}
	if err := s.ask(ctx, w, authorizer.ActionConversationCommit, c.ID, facts(c, commitFields(change))); err != nil {
		return nil, err
	}
	if err := view.Merge(m.Commit); err != nil {
		return nil, err
	}
	if err := view.VerifyGroupInfo(in.GroupInfo); err != nil {
		return nil, apierr.Wrap(apierr.CodeInvalid, fmt.Errorf("the group info does not describe the new epoch: %w", err))
	}
	if !carriesTreeAndKey(in.GroupInfo, view) {
		return nil, apierr.New(apierr.CodeInvalid, "the group info carries the ratchet tree and the external public key")
	}
	st, err := messaging.ParseState(view.Extensions())
	if err != nil {
		return nil, err
	}
	next := *c
	next.Kind, next.Level, next.People, next.Owners = st.Kind, st.Level, st.People, st.Owners
	next.Epoch = view.Epoch()
	next.GroupInfo = in.GroupInfo
	if next.View, err = view.MarshalBinary(); err != nil {
		return nil, err
	}
	next.Members = spans(c.Members, changes, next.Epoch)

	msg.Kind = store.KindCommit
	a := &store.Append{Message: msg, State: &next}
	var added []mls.Member
	for _, m := range changes.Added {
		if !changes.ExternalJoin {
			added = append(added, m)
		}
	}
	if len(added) > 0 {
		refs, err := mls.WelcomeKeyPackageRefs(in.Welcome)
		if err != nil {
			return nil, apierr.Wrap(apierr.CodeInvalid, fmt.Errorf("a commit that adds a leaf carries its Welcome: %w", err))
		}
		if len(refs) != len(added) {
			return nil, apierr.New(apierr.CodeInvalid, "the Welcome is not for every leaf the commit adds")
		}
		for _, m := range added {
			id, err := messaging.ParseCredential(m.Credential)
			if err != nil {
				return nil, err
			}
			if id.Latere() {
				continue // the assistant's member joins in process
			}
			wid, err := newID()
			if err != nil {
				return nil, err
			}
			a.Welcomes = append(a.Welcomes, store.Welcome{ID: wid, Person: id.Person, Device: id.Device,
				Data: in.Welcome, Notice: changes.AuthenticatedData})
		}
	} else if len(in.Welcome) > 0 {
		return nil, apierr.New(apierr.CodeInvalid, "a commit that adds no leaf carries no Welcome")
	}
	return a, nil
}

// carriesTreeAndKey reports whether a group info is of the view's group
// and epoch and lets a device join from it alone: it carries the ratchet
// tree, which VerifyGroupInfo held to the view's, and the external
// public key, which only members can check.
func carriesTreeAndKey(groupInfo []byte, view *mls.PublicGroup) bool {
	info, err := mls.PeekMessage(groupInfo)
	if err != nil || info.WireFormat != mls.WireFormatGroupInfo || !bytes.Equal(info.GroupID, view.GroupID()) || info.Epoch != view.Epoch() {
		return false
	}
	return slices.Contains(info.Extensions, mls.ExtensionRatchetTree) && slices.Contains(info.Extensions, mls.ExtensionExternalPub)
}

// spans moves the devices' spans of the log over a commit that starts
// an epoch: a removed device's ends there, an added one's starts there.
func spans(before []store.Member, ch mls.Changes, epoch uint64) []store.Member {
	out := make([]store.Member, len(before))
	copy(out, before)
	for _, m := range ch.Removed {
		id, err := messaging.ParseCredential(m.Credential)
		if err != nil || id.Latere() {
			continue
		}
		for i := range out {
			if out[i].Person == id.Person && out[i].Device == id.Device && out[i].Until == 0 {
				out[i].Until = epoch
			}
		}
	}
	for _, m := range ch.Added {
		id, err := messaging.ParseCredential(m.Credential)
		if err != nil || id.Latere() {
			continue
		}
		out = append(out, store.Member{Person: id.Person, Device: id.Device, Since: epoch})
	}
	return out
}

func commitFields(ch *messaging.Change) map[string]any {
	var changes, removed []string
	if len(ch.Joined) > 0 {
		changes = append(changes, authorizer.ChangeAddPeople)
	}
	removed = append(removed, ch.Left...)
	for _, r := range ch.Removed {
		removed = append(removed, r.Person)
	}
	if len(removed) > 0 {
		changes = append(changes, authorizer.ChangeRemovePeople)
	}
	if !slices.Equal(ch.Before.Owners, ch.After.Owners) {
		changes = append(changes, authorizer.ChangeOwners)
	}
	if ch.Before.Level != ch.After.Level {
		changes = append(changes, authorizer.ChangeLevel)
	}
	if len(ch.DevicesAdded) > 0 || len(ch.DevicesRemoved) > 0 {
		changes = append(changes, authorizer.ChangeDevices)
	}
	level, _ := ch.After.Level.MarshalText()
	return map[string]any{
		authorizer.FieldChanges:      nonNil(changes),
		authorizer.FieldAddPeople:    nonNil(ch.Joined),
		authorizer.FieldRemovePeople: nonNil(removed),
		authorizer.FieldNewOwners:    nonNil(ch.After.Owners),
		authorizer.FieldNewLevel:     string(level),
	}
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Page is one read of a conversation's log: the messages the calling
// device may read, and the sequence number to read after next, which
// passes the messages of epochs it was not a leaf in.
type Page struct {
	Messages []store.Message
	Next     int64
}

// Messages lists the messages after a sequence number that the calling
// device may read, waiting up to wait for one when there are none.
func (s *Service) Messages(ctx context.Context, w Who, id string, after int64, limit int, wait time.Duration) (*Page, error) {
	c, err := s.conversation(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.ask(ctx, w, authorizer.ActionConversationRead, id, facts(&c, nil)); err != nil {
		return nil, err
	}
	wait = min(max(wait, 0), MaxWait)
	deadline := s.now().Add(wait)
	for {
		ch := s.hub.wait(id)
		page, err := s.page(ctx, w, id, after, limit)
		if err != nil || page.Next > after || !deadline.After(s.now()) {
			s.hub.forget(id, ch)
			return page, err
		}
		t := time.NewTimer(deadline.Sub(s.now()))
		expired := false
		select {
		case <-ch:
		case <-t.C:
			expired = true
		case <-ctx.Done():
		}
		t.Stop()
		s.hub.forget(id, ch)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if expired { // the wait ends with its timer, whatever the clock says
			return s.page(ctx, w, id, after, limit)
		}
	}
}

func (s *Service) page(ctx context.Context, w Who, id string, after int64, limit int) (*Page, error) {
	c, err := s.conversation(ctx, id)
	if err != nil {
		return nil, err
	}
	msgs, err := s.store.Messages(ctx, id, after, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	p := &Page{Next: after}
	for _, m := range msgs {
		if c.MayRead(w.Person, w.Device, m.Epoch) {
			p.Messages = append(p.Messages, m)
		}
		p.Next = m.Seq
	}
	return p, nil
}

// GroupInfo is the latest group info, for a device of one of the
// conversation's people to join from.
func (s *Service) GroupInfo(ctx context.Context, w Who, id string) ([]byte, error) {
	c, err := s.Get(ctx, w, id)
	if err != nil {
		return nil, err
	}
	if !c.Has(w.Person) {
		return nil, apierr.New(apierr.CodeForbidden, "the caller is not one of the conversation's people")
	}
	return c.GroupInfo, nil
}

// Welcomes lists the welcomes filed for the calling device.
func (s *Service) Welcomes(ctx context.Context, w Who) ([]store.Welcome, error) {
	ws, err := s.store.Welcomes(ctx, w.Person, w.Device)
	if err != nil {
		return nil, err
	}
	var out []store.Welcome
	for _, wl := range ws {
		c, err := s.store.Conversation(ctx, wl.Conversation)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := s.ask(ctx, w, authorizer.ActionConversationRead, c.ID, facts(&c, nil)); err != nil {
			if e := apierr.Classify(err); e.Code == apierr.CodeForbidden {
				continue
			}
			return nil, err
		}
		out = append(out, wl)
	}
	return out, nil
}

// DeleteWelcome drops a welcome the calling device has joined with.
func (s *Service) DeleteWelcome(ctx context.Context, w Who, id string) error {
	if err := s.store.DeleteWelcome(ctx, w.Person, w.Device, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return apierr.New(apierr.CodeNotFound, "no such welcome")
		}
		return err
	}
	return nil
}

// Sweep deletes the messages and welcomes older than the retention.
func (s *Service) Sweep(ctx context.Context, retention time.Duration) (int, error) {
	return s.store.DeleteMessagesBefore(ctx, s.now().Add(-retention))
}
