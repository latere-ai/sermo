// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package memory is the store held in the process, for a trial and the
// tests. Nothing survives a restart.
package memory

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/internal/store"
)

// Store is the store in memory.
type Store struct {
	mu        sync.Mutex
	now       func() time.Time
	devices   map[string]map[string]messaging.DeviceRecord // person, id
	revoked   map[string][]messaging.Revocation
	recovery  map[string][]byte
	transfers map[[2]string][]byte
	packages  map[[2]string][]store.KeyPackage // one-time ones, oldest first
	resorts   map[[2]string]store.KeyPackage
	convs     map[string]*store.Conversation
	log       map[string][]store.Message
	welcomes  []store.Welcome
	// backup is each person's records of each conversation, in the order
	// they were stored, and backupBytes what each person's hold.
	backup      map[[2]string][]store.BackupRecord
	backupBytes map[string]int64
	backupSeq   int64
}

// New returns an empty store. now is the clock; nil takes time.Now.
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		now: now, devices: map[string]map[string]messaging.DeviceRecord{}, revoked: map[string][]messaging.Revocation{},
		recovery:  map[string][]byte{},
		transfers: map[[2]string][]byte{}, packages: map[[2]string][]store.KeyPackage{}, resorts: map[[2]string]store.KeyPackage{},
		convs: map[string]*store.Conversation{}, log: map[string][]store.Message{},
		backup: map[[2]string][]store.BackupRecord{}, backupBytes: map[string]int64{},
	}
}

func cloneRecord(r messaging.DeviceRecord) messaging.DeviceRecord {
	r.SignatureKey = bytes.Clone(r.SignatureKey)
	r.EncryptionKey = bytes.Clone(r.EncryptionKey)
	r.Vouch = bytes.Clone(r.Vouch)
	r.Possession = bytes.Clone(r.Possession)
	return r
}

func cloneRevocation(v messaging.Revocation) messaging.Revocation {
	v.Key = bytes.Clone(v.Key)
	v.Signature = bytes.Clone(v.Signature)
	keep := make([][]byte, len(v.Keep))
	for i, k := range v.Keep {
		keep[i] = bytes.Clone(k)
	}
	v.Keep = keep
	return v
}

func cloneConversation(c *store.Conversation) store.Conversation {
	out := *c
	out.People = slices.Clone(c.People)
	out.Owners = slices.Clone(c.Owners)
	out.View = bytes.Clone(c.View)
	out.GroupInfo = bytes.Clone(c.GroupInfo)
	out.Members = slices.Clone(c.Members)
	return out
}

// decide runs a directory write's check over copies of the person's
// directory. The caller holds s.mu, which no other write of the
// directory takes while check runs.
func (s *Store) decide(person string, check store.DirectoryCheck) (bool, error) {
	if check == nil {
		return true, nil
	}
	return check(s.records(person), s.revocations(person))
}

// records is copies of a person's records, by id. The caller holds s.mu.
func (s *Store) records(person string) []messaging.DeviceRecord {
	out := make([]messaging.DeviceRecord, 0, len(s.devices[person]))
	for _, r := range s.devices[person] {
		out = append(out, cloneRecord(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// revocations is copies of a person's revocations, in the order they
// came. The caller holds s.mu.
func (s *Store) revocations(person string) []messaging.Revocation {
	out := make([]messaging.Revocation, len(s.revoked[person]))
	for i, v := range s.revoked[person] {
		out[i] = cloneRevocation(v)
	}
	return out
}

// PutDevice adds or replaces a record when check says to.
func (s *Store) PutDevice(_ context.Context, r messaging.DeviceRecord, check store.DirectoryCheck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if write, err := s.decide(r.Person, check); err != nil || !write {
		return err
	}
	if s.devices[r.Person] == nil {
		s.devices[r.Person] = map[string]messaging.DeviceRecord{}
	}
	s.devices[r.Person][r.ID] = cloneRecord(r)
	return nil
}

// Devices lists a person's records by id.
func (s *Store) Devices(_ context.Context, person string) ([]messaging.DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records(person), nil
}

// AddRevocation keeps a revocation once and drops the device's keys, when
// check says to.
func (s *Store) AddRevocation(_ context.Context, v messaging.Revocation, device string, check store.DirectoryCheck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if write, err := s.decide(v.Person, check); err != nil || !write {
		return err
	}
	if !slices.ContainsFunc(s.revoked[v.Person], func(o messaging.Revocation) bool { return bytes.Equal(o.Signature, v.Signature) }) {
		s.revoked[v.Person] = append(s.revoked[v.Person], cloneRevocation(v))
	}
	if device != "" {
		k := [2]string{v.Person, device}
		delete(s.packages, k)
		delete(s.resorts, k)
		delete(s.transfers, k)
	}
	return nil
}

// Revocations lists a person's revocations in the order they came.
func (s *Store) Revocations(_ context.Context, person string) ([]messaging.Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revocations(person), nil
}

// PutRecovery stores the wrapped backup key.
func (s *Store) PutRecovery(_ context.Context, person string, wrapped []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recovery[person] = bytes.Clone(wrapped)
	return nil
}

// Recovery is a person's wrapped backup key.
func (s *Store) Recovery(_ context.Context, person string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.recovery[person]
	if !ok {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(w), nil
}

// PutTransfer leaves a sealed backup key for a device.
func (s *Store) PutTransfer(_ context.Context, person, device string, sealed []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transfers[[2]string{person, device}] = bytes.Clone(sealed)
	return nil
}

// TakeTransfer returns and deletes what was left for a device.
func (s *Store) TakeTransfer(_ context.Context, person, device string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]string{person, device}
	sealed, ok := s.transfers[k]
	if !ok {
		return nil, store.ErrNotFound
	}
	delete(s.transfers, k)
	return sealed, nil
}

// PutBackupRecords stores backup records, keeping the first of an id.
func (s *Store) PutBackupRecords(_ context.Context, person, conversation string, records []store.BackupRecord, limit int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]string{person, conversation}
	have := map[string]bool{}
	for _, r := range s.backup[k] {
		have[r.ID] = true
	}
	var fresh []store.BackupRecord
	var size int64
	for _, r := range records {
		if have[r.ID] {
			continue
		}
		have[r.ID] = true
		r.Sealed = bytes.Clone(r.Sealed)
		fresh = append(fresh, r)
		size += int64(len(r.Sealed))
	}
	if s.backupBytes[person]+size > limit {
		return 0, store.ErrFull
	}
	for _, r := range fresh {
		s.backupSeq++
		r.Seq, r.Created = s.backupSeq, s.now().UTC()
		s.backup[k] = append(s.backup[k], r)
	}
	s.backupBytes[person] += size
	return len(fresh), nil
}

// BackupRecords lists backup records by the place they were stored at.
func (s *Store) BackupRecords(_ context.Context, person, conversation string, cursor int64, newest bool, limit int) ([]store.BackupRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 {
		return nil, nil
	}
	all := s.backup[[2]string{person, conversation}]
	var out []store.BackupRecord
	if newest {
		for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
			if cursor == 0 || all[i].Seq < cursor {
				out = append(out, all[i])
			}
		}
	} else {
		for _, r := range all {
			if r.Seq > cursor && len(out) < limit {
				out = append(out, r)
			}
		}
	}
	for i := range out {
		out[i].Sealed = bytes.Clone(out[i].Sealed)
	}
	return out, nil
}

// AddKeyPackages adds key packages.
func (s *Store) AddKeyPackages(_ context.Context, kps []store.KeyPackage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, kp := range kps {
		kp.Data = bytes.Clone(kp.Data)
		if kp.Created.IsZero() {
			kp.Created = s.now()
		}
		k := [2]string{kp.Person, kp.Device}
		if kp.LastResort {
			s.resorts[k] = kp
			continue
		}
		s.packages[k] = append(s.packages[k], kp)
	}
	return nil
}

// CountKeyPackages counts a device's key packages.
func (s *Store) CountKeyPackages(_ context.Context, person, device string) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]string{person, device}
	_, resort := s.resorts[k]
	return len(s.packages[k]), resort, nil
}

// ClaimKeyPackage hands out one key package.
func (s *Store) ClaimKeyPackage(_ context.Context, person, device string) (store.KeyPackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := [2]string{person, device}
	if kps := s.packages[k]; len(kps) > 0 {
		s.packages[k] = kps[1:]
		return kps[0], nil
	}
	if kp, ok := s.resorts[k]; ok {
		kp.Data = bytes.Clone(kp.Data)
		return kp, nil
	}
	return store.KeyPackage{}, store.ErrNotFound
}

// CreateConversation stores a new conversation.
func (s *Store) CreateConversation(_ context.Context, c store.Conversation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.convs[c.ID]; ok {
		return store.ErrExists
	}
	now := s.now()
	c.Seq, c.Version, c.Created, c.Updated = 0, 0, now, now
	cc := cloneConversation(&c)
	s.convs[c.ID] = &cc
	return nil
}

// Conversation reads a conversation.
func (s *Store) Conversation(_ context.Context, id string) (store.Conversation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.convs[id]
	if !ok {
		return store.Conversation{}, store.ErrNotFound
	}
	return cloneConversation(c), nil
}

// Conversations lists a person's conversations by id.
func (s *Store) Conversations(_ context.Context, person, after string, limit int) ([]store.Conversation, error) {
	if limit < 1 {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Conversation
	for id, c := range s.convs {
		if id > after && c.Has(person) {
			out = append(out, cloneConversation(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Append appends a message.
func (s *Store) Append(_ context.Context, id string, version int64, a store.Append) (store.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.convs[id]
	if !ok {
		return store.Message{}, store.ErrNotFound
	}
	if c.Version != version {
		return store.Message{}, store.ErrConflict
	}
	now := s.now()
	m := a.Message
	m.Conversation, m.Seq, m.Created = id, c.Seq+1, now
	// The log keeps bytes of its own, shared with neither the caller's
	// message nor the one returned.
	kept := m
	kept.Data = bytes.Clone(m.Data)
	if a.State != nil {
		next := cloneConversation(a.State)
		next.ID, next.Created = id, c.Created
		next.Version = c.Version + 1
		*c = next
	}
	c.Seq, c.Updated = m.Seq, now
	s.log[id] = append(s.log[id], kept)
	for _, w := range a.Welcomes {
		w.Conversation, w.Seq, w.Created = id, m.Seq, now
		w.Data, w.Notice = bytes.Clone(w.Data), bytes.Clone(w.Notice)
		s.welcomes = append(s.welcomes, w)
	}
	return m, nil
}

// Messages lists messages after a sequence number.
func (s *Store) Messages(_ context.Context, id string, after int64, limit int) ([]store.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.convs[id]; !ok {
		return nil, store.ErrNotFound
	}
	if limit < 1 {
		return nil, nil
	}
	var out []store.Message
	for _, m := range s.log[id] {
		if m.Seq > after {
			m.Data = bytes.Clone(m.Data)
			out = append(out, m)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

// Welcomes lists a device's welcomes.
func (s *Store) Welcomes(_ context.Context, person, device string) ([]store.Welcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Welcome
	for _, w := range s.welcomes {
		if w.Person == person && w.Device == device {
			w.Data, w.Notice = bytes.Clone(w.Data), bytes.Clone(w.Notice)
			out = append(out, w)
		}
	}
	return out, nil
}

// DeleteWelcome deletes a device's welcome.
func (s *Store) DeleteWelcome(_ context.Context, person, device, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, w := range s.welcomes {
		if w.ID == id && w.Person == person && w.Device == device {
			s.welcomes = slices.Delete(s.welcomes, i, i+1)
			return nil
		}
	}
	return store.ErrNotFound
}

// DeleteMessagesBefore deletes old messages and welcomes.
func (s *Store) DeleteMessagesBefore(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, msgs := range s.log {
		kept := msgs[:0]
		for _, m := range msgs {
			if m.Created.Before(before) {
				n++
				continue
			}
			kept = append(kept, m)
		}
		s.log[id] = kept
	}
	s.welcomes = slices.DeleteFunc(s.welcomes, func(w store.Welcome) bool { return w.Created.Before(before) })
	return n, nil
}

var _ store.Store = (*Store)(nil)
