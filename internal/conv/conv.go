// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package conv is what sermod does with what devices send: the
// directory, key packages, and each conversation's group, checked with
// latere.ai/x/sdk-go/mls and the rules of latere.ai/x/sdk-go/messaging
// before anything is kept (specs/002-api.md). It answers in the errors
// of package apierr and asks the authorizer every question the API's
// table names.
package conv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/sdk-go/messaging"
	"latere.ai/x/sdk-go/mls"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/apierr"
	"latere.ai/x/sermo/internal/store"
)

// The limits a request is held to.
const (
	// MaxKeyPackagesPerCall is how many key packages one publish carries.
	MaxKeyPackagesPerCall = 100
	// MaxKeyPackagesPerDevice is how many one-time key packages a device
	// keeps at once.
	MaxKeyPackagesPerDevice = 200
	// MaxMessageBytes is the largest MLS message: the largest payload
	// with its framing.
	MaxMessageBytes = messaging.MaxPayloadBytes + 4<<10
	// MaxSealedBytes is the largest wrapped backup key or sealed
	// transfer.
	MaxSealedBytes = 4 << 10
	// MaxListLimit is the most one page of a list holds, and
	// DefaultListLimit the size of a page that names none.
	MaxListLimit     = 200
	DefaultListLimit = 50
	// MaxWait is the longest a read of messages waits for one.
	MaxWait = 30 * time.Second
)

// ServiceIdentity is the identity of Sermo's credential as the groups'
// external sender.
const ServiceIdentity = "service"

// Service is sermod's work, over a store and an authorizer.
type Service struct {
	store      store.Store
	authorizer access.Authorizer
	signer     *mls.SignatureKey
	install    ed25519.PublicKey
	now        func() time.Time
	hub        hub
}

// Options build a Service.
type Options struct {
	Store      store.Store
	Authorizer access.Authorizer
	// ServiceKey is the external sender's Ed25519 private key.
	ServiceKey ed25519.PrivateKey
	// Installation is the key that attests the assistant's member; nil
	// admits none.
	Installation ed25519.PublicKey
	Now          func() time.Time
}

// New builds the service.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Authorizer == nil || len(o.ServiceKey) != ed25519.PrivateKeySize {
		return nil, errors.New("conv: a store, an authorizer and the service key are needed")
	}
	signer, err := mls.NewSignatureKey(messaging.Suite, o.ServiceKey.Seed())
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Service{store: o.Store, authorizer: o.Authorizer, signer: signer, install: o.Installation, now: now,
		hub: hub{waiters: map[string][]chan struct{}{}}}, nil
}

// ExternalSender is Sermo as each group names it: the one sender from
// outside the group, which proposes removals.
func (s *Service) ExternalSender() mls.ExternalSender {
	return mls.ExternalSender{SignatureKey: s.signer.PublicKey(), Credential: mls.BasicCredential([]byte(ServiceIdentity))}
}

// Who is the caller of one request: the verified token, the person it
// is, and the device it speaks for, empty for a request that names none.
type Who struct {
	Caller  access.Caller
	Person  string
	Device  string
	Request *http.Request
}

func (s *Service) ask(ctx context.Context, w Who, action, id string, fields map[string]any) error {
	d, err := s.authorizer.Authorize(ctx, w.Caller, w.Request, action, authz.NewResource(authorizer.Kind(action), id, fields))
	if err != nil {
		if errors.Is(err, access.ErrUnavailable) {
			return apierr.Wrap(apierr.CodeAuthorizerUnavailable, err)
		}
		return err
	}
	if !d.Allow {
		return apierr.New(apierr.CodeForbidden, d.Reason)
	}
	return nil
}

func facts(c *store.Conversation, extra map[string]any) map[string]any {
	kind, _ := c.Kind.MarshalText()
	level, _ := c.Level.MarshalText()
	f := map[string]any{
		authorizer.FieldConversationKind: string(kind),
		authorizer.FieldPeople:           slices.Clone(c.People),
		authorizer.FieldOwners:           slices.Clone(c.Owners),
		authorizer.FieldLevel:            string(level),
	}
	maps.Copy(f, extra)
	return f
}

// records is a person's records and revocations as the store holds them.
func (s *Service) records(ctx context.Context, person string) ([]messaging.DeviceRecord, []messaging.Revocation, error) {
	records, err := s.store.Devices(ctx, person)
	if err != nil {
		return nil, nil, err
	}
	revocations, err := s.store.Revocations(ctx, person)
	if err != nil {
		return nil, nil, err
	}
	return records, revocations, nil
}

func (s *Service) directory(ctx context.Context, person string) (*messaging.Directory, error) {
	records, revocations, err := s.records(ctx, person)
	if err != nil {
		return nil, err
	}
	d, _ := messaging.NewDirectory(person, records, revocations)
	return d, nil
}

func (s *Service) policy(ctx context.Context) *messaging.Policy {
	return &messaging.Policy{Installation: s.install, Directory: func(person string) (*messaging.Directory, error) {
		return s.directory(ctx, person)
	}}
}

// CheckDevice checks that a device is one of the person's and stands in
// their directory: what every request a device makes needs.
func (s *Service) CheckDevice(ctx context.Context, person, device string) error {
	d, err := s.directory(ctx, person)
	if err != nil {
		return err
	}
	if _, ok := d.Device(device); !ok {
		return apierr.New(apierr.CodeNotYourDevice, "the device is not one of the caller's, or it was removed")
	}
	return nil
}

// putRecord checks a record of the caller's, new or vouched for again
// under its id with the same keys, against their directory, and keeps
// it when it stands with the others.
func (s *Service) putRecord(ctx context.Context, w Who, r messaging.DeviceRecord, stands func(*messaging.Directory) bool) (fresh bool, err error) {
	records, revocations, err := s.records(ctx, w.Person)
	if err != nil {
		return false, err
	}
	rest := records[:0:0]
	fresh = true
	for _, old := range records {
		if old.ID != r.ID {
			rest = append(rest, old)
			continue
		}
		if !bytes.Equal(old.SignatureKey, r.SignatureKey) || !bytes.Equal(old.EncryptionKey, r.EncryptionKey) || old.Kind != r.Kind {
			return false, apierr.New(apierr.CodeExists, "the record's id is registered with other keys")
		}
		if old.Voucher == r.Voucher && bytes.Equal(old.Vouch, r.Vouch) {
			return false, nil // registered already
		}
		fresh = false
	}
	if fresh && len(records) >= messaging.MaxRecords {
		return false, apierr.New(apierr.CodeTooLarge, fmt.Sprintf("a person has at most %d records", messaging.MaxRecords))
	}
	d, _ := messaging.NewDirectory(w.Person, append(rest, r), revocations)
	if d.Revoked(r.SignatureKey) {
		return false, apierr.New(apierr.CodeExists, "a revoked key is not registered again")
	}
	if !stands(d) {
		return false, apierr.New(apierr.CodeInvalid, "the record does not verify against the caller's records")
	}
	return fresh, nil
}

// RegisterDevice registers a device record of the caller's, vouched for
// by another of the caller's records or by itself as a new root, or
// replaces it with the same keys vouched for again, as a person does for
// a device a revoked key vouched for.
func (s *Service) RegisterDevice(ctx context.Context, w Who, r messaging.DeviceRecord) error {
	if r.Person != w.Person || r.Kind != messaging.RecordDevice {
		return apierr.New(apierr.CodeInvalid, "the record is a device record of the caller")
	}
	if err := s.ask(ctx, w, authorizer.ActionDeviceRegister, r.ID, map[string]any{
		authorizer.FieldPerson: w.Person, authorizer.FieldRoot: r.Root(),
	}); err != nil {
		return err
	}
	if _, err := s.putRecord(ctx, w, r, func(d *messaging.Directory) bool {
		got, ok := d.Device(r.ID)
		return ok && bytes.Equal(got.Vouch, r.Vouch)
	}); err != nil {
		return err
	}
	return s.store.PutDevice(ctx, r)
}

// Directory is a person's directory as Sermo holds it, for the caller to
// verify with messaging.NewDirectory.
type Directory struct {
	Records     []messaging.DeviceRecord
	Revocations []messaging.Revocation
}

// Devices lists every record and revocation of a person.
func (s *Service) Devices(ctx context.Context, w Who, person string) (*Directory, error) {
	if err := s.ask(ctx, w, authorizer.ActionDeviceList, "", map[string]any{authorizer.FieldPerson: person}); err != nil {
		return nil, err
	}
	records, revocations, err := s.records(ctx, person)
	if err != nil {
		return nil, err
	}
	return &Directory{Records: records, Revocations: revocations}, nil
}

// Revoke keeps a revocation one of the caller's records signed. The
// revoked device's key packages and transfer go, and Sermo proposes the
// removal of every leaf with the revoked key from every conversation of
// the caller's.
func (s *Service) Revoke(ctx context.Context, w Who, v messaging.Revocation) error {
	if v.Person != w.Person {
		return apierr.New(apierr.CodeInvalid, "the revocation is of a key of the caller")
	}
	records, revocations, err := s.records(ctx, w.Person)
	if err != nil {
		return err
	}
	if len(revocations) >= messaging.MaxRecords {
		return apierr.New(apierr.CodeTooLarge, fmt.Sprintf("a person has at most %d revocations", messaging.MaxRecords))
	}
	d, _ := messaging.NewDirectory(w.Person, records, append(revocations, v))
	if !slices.ContainsFunc(d.Revocations(), func(o messaging.Revocation) bool { return bytes.Equal(o.Signature, v.Signature) }) {
		return apierr.New(apierr.CodeInvalid, "the revocation is not signed by a record of the caller's")
	}
	device := ""
	for _, r := range records {
		if bytes.Equal(r.SignatureKey, v.Key) {
			device = r.ID
		}
	}
	if err := s.ask(ctx, w, authorizer.ActionDeviceDelete, device, map[string]any{authorizer.FieldPerson: w.Person}); err != nil {
		return err
	}
	if err := s.store.AddRevocation(ctx, v, device); err != nil {
		return err
	}
	return s.proposeRemovals(ctx, w.Person, v.Key)
}

// proposeRemovals proposes, as the external sender, the removal of every
// leaf with a revoked key from every conversation of its person.
func (s *Service) proposeRemovals(ctx context.Context, person string, key []byte) error {
	var errs []error
	after := ""
	for {
		page, err := s.store.Conversations(ctx, person, after, MaxListLimit)
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		for _, c := range page {
			if err := s.proposeRemoval(ctx, c.ID, key); err != nil {
				errs = append(errs, fmt.Errorf("conv: removing a revoked key's leaf from %s: %w", c.ID, err))
			}
		}
		if len(page) < MaxListLimit {
			return errors.Join(errs...)
		}
		after = page[len(page)-1].ID
	}
}

func (s *Service) proposeRemoval(ctx context.Context, id string, key []byte) error {
	for range 3 {
		c, err := s.store.Conversation(ctx, id)
		if err != nil {
			return err
		}
		view, err := mls.UnmarshalPublicGroup(c.View, s.policy(ctx).Config())
		if err != nil {
			return err
		}
		leaf, found := uint32(0), false
		for _, m := range view.Members() {
			if bytes.Equal(m.SignatureKey, key) {
				leaf, found = m.Leaf, true
			}
		}
		if !found {
			return nil
		}
		msg, err := mls.ProposeExternalRemove(s.signer, view.GroupID(), view.Epoch(), 0, leaf)
		if err != nil {
			return err
		}
		if slices.ContainsFunc(view.PendingProposals(), func(p mls.Proposal) bool {
			return p.Sender.Kind == mls.SenderExternal && p.Kind == mls.ProposalRemove && p.Leaf == leaf
		}) {
			return nil // proposed already this epoch
		}
		if _, err := view.Process(msg); err != nil {
			return err
		}
		next := c
		if next.View, err = view.MarshalBinary(); err != nil {
			return err
		}
		_, err = s.store.Append(ctx, id, c.Version, store.Append{
			Message: store.Message{Epoch: view.Epoch(), Kind: store.KindProposal, Data: msg},
			State:   &next,
		})
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			return err
		}
		s.hub.wake(id)
		return nil
	}
	return store.ErrConflict
}

// Recovery is a person's recovery record and wrapped backup key.
type Recovery struct {
	Record  messaging.DeviceRecord
	Wrapped []byte
}

// PutRecovery registers the caller's recovery record, vouched for by one
// of their devices, with the backup key wrapped under the recovery key.
// A person has one recovery record that stands: the one it replaces is
// revoked first.
func (s *Service) PutRecovery(ctx context.Context, w Who, r messaging.DeviceRecord, wrapped []byte) error {
	if r.Person != w.Person || r.Kind != messaging.RecordRecovery {
		return apierr.New(apierr.CodeInvalid, "the record is a recovery record of the caller")
	}
	if len(wrapped) == 0 || len(wrapped) > MaxSealedBytes {
		return apierr.New(apierr.CodeInvalid, "the wrapped backup key is missing or too large")
	}
	if err := s.ask(ctx, w, authorizer.ActionBackupRecovery, "", map[string]any{authorizer.FieldPerson: w.Person}); err != nil {
		return err
	}
	before, err := s.directory(ctx, w.Person)
	if err != nil {
		return err
	}
	if old, ok := before.Recovery(); ok && old.ID != r.ID {
		return apierr.New(apierr.CodeExists, "the recovery record it replaces is revoked first")
	}
	if _, err := s.putRecord(ctx, w, r, func(d *messaging.Directory) bool {
		got, ok := d.Recovery()
		return ok && got.ID == r.ID && bytes.Equal(got.Vouch, r.Vouch)
	}); err != nil {
		return err
	}
	if err := s.store.PutDevice(ctx, r); err != nil {
		return err
	}
	return s.store.PutRecovery(ctx, w.Person, wrapped)
}

// GetRecovery is the caller's recovery record and wrapped backup key.
func (s *Service) GetRecovery(ctx context.Context, w Who) (*Recovery, error) {
	if err := s.ask(ctx, w, authorizer.ActionBackupRecovery, "", map[string]any{authorizer.FieldPerson: w.Person}); err != nil {
		return nil, err
	}
	wrapped, err := s.store.Recovery(ctx, w.Person)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.New(apierr.CodeNotFound, "no recovery key is registered")
	}
	if err != nil {
		return nil, err
	}
	d, err := s.directory(ctx, w.Person)
	if err != nil {
		return nil, err
	}
	r, ok := d.Recovery()
	if !ok {
		return nil, apierr.New(apierr.CodeNotFound, "no recovery key is registered")
	}
	return &Recovery{Record: r, Wrapped: wrapped}, nil
}

// PutTransfer leaves the backup key, sealed to one of the caller's
// devices, for that device to fetch once.
func (s *Service) PutTransfer(ctx context.Context, w Who, device string, sealed []byte) error {
	if len(sealed) == 0 || len(sealed) > MaxSealedBytes {
		return apierr.New(apierr.CodeInvalid, "the sealed backup key is missing or too large")
	}
	if err := s.CheckDevice(ctx, w.Person, device); err != nil {
		return apierr.New(apierr.CodeNotFound, "the device is not registered")
	}
	if err := s.ask(ctx, w, authorizer.ActionDeviceVouch, device, map[string]any{authorizer.FieldPerson: w.Person}); err != nil {
		return err
	}
	return s.store.PutTransfer(ctx, w.Person, device, sealed)
}

// TakeTransfer is what was left for the calling device, once.
func (s *Service) TakeTransfer(ctx context.Context, w Who, device string) ([]byte, error) {
	if device != w.Device {
		return nil, apierr.New(apierr.CodeForbidden, "a device fetches what was left for itself")
	}
	if err := s.ask(ctx, w, authorizer.ActionDeviceVouch, device, map[string]any{authorizer.FieldPerson: w.Person}); err != nil {
		return nil, err
	}
	sealed, err := s.store.TakeTransfer(ctx, w.Person, device)
	if errors.Is(err, store.ErrNotFound) {
		return nil, apierr.New(apierr.CodeNotFound, "nothing was left for this device")
	}
	return sealed, err
}

// PublishKeyPackages adds key packages of the calling device, each made
// for the profile with the device's credential and signature key.
func (s *Service) PublishKeyPackages(ctx context.Context, w Who, packages [][]byte, lastResort []byte) error {
	if len(packages) > MaxKeyPackagesPerCall {
		return apierr.New(apierr.CodeTooLarge, fmt.Sprintf("at most %d key packages a call", MaxKeyPackagesPerCall))
	}
	if err := s.ask(ctx, w, authorizer.ActionKeyPackagePublish, "", map[string]any{
		authorizer.FieldPerson: w.Person, authorizer.FieldDevice: w.Device,
	}); err != nil {
		return err
	}
	d, err := s.directory(ctx, w.Person)
	if err != nil {
		return err
	}
	rec, ok := d.Device(w.Device)
	if !ok {
		return apierr.New(apierr.CodeNotYourDevice, "the device was removed")
	}
	n, _, err := s.store.CountKeyPackages(ctx, w.Person, w.Device)
	if err != nil {
		return err
	}
	if n+len(packages) > MaxKeyPackagesPerDevice {
		return apierr.New(apierr.CodeTooLarge, fmt.Sprintf("a device keeps at most %d key packages", MaxKeyPackagesPerDevice))
	}
	check := func(b []byte, last bool) (store.KeyPackage, error) {
		kp, err := mls.ParseKeyPackage(b)
		if err != nil {
			return store.KeyPackage{}, apierr.Wrap(apierr.CodeInvalid, err)
		}
		id, err := messaging.CheckKeyPackage(kp)
		if err != nil {
			return store.KeyPackage{}, apierr.Wrap(apierr.CodeInvalid, err)
		}
		if id.Person != w.Person || id.Device != w.Device || !bytes.Equal(kp.SignatureKey(), rec.SignatureKey) {
			return store.KeyPackage{}, apierr.New(apierr.CodeInvalid, "a key package names another device or another key")
		}
		return store.KeyPackage{Ref: hex.EncodeToString(kp.Ref()), Person: w.Person, Device: w.Device, Data: kp.Bytes(), LastResort: last}, nil
	}
	var kps []store.KeyPackage
	for _, b := range packages {
		kp, err := check(b, false)
		if err != nil {
			return err
		}
		kps = append(kps, kp)
	}
	if lastResort != nil {
		kp, err := check(lastResort, true)
		if err != nil {
			return err
		}
		kps = append(kps, kp)
	}
	return s.store.AddKeyPackages(ctx, kps)
}

// KeyPackageCount is how many key packages the calling device has left.
func (s *Service) KeyPackageCount(ctx context.Context, w Who) (n int, lastResort bool, err error) {
	if err := s.ask(ctx, w, authorizer.ActionKeyPackagePublish, "", map[string]any{
		authorizer.FieldPerson: w.Person, authorizer.FieldDevice: w.Device,
	}); err != nil {
		return 0, false, err
	}
	return s.store.CountKeyPackages(ctx, w.Person, w.Device)
}

// Claimed is one device's key package a claim handed out.
type Claimed struct {
	Device     string
	KeyPackage []byte
}

// ClaimKeyPackages hands out one key package of each device of a person,
// for a conversation the caller is one of the people of.
func (s *Service) ClaimKeyPackages(ctx context.Context, w Who, person, conversation string) ([]Claimed, error) {
	c, err := s.conversation(ctx, conversation)
	if err != nil {
		return nil, err
	}
	if !c.Has(w.Person) {
		return nil, apierr.New(apierr.CodeNotFound, "no such conversation")
	}
	if err := s.ask(ctx, w, authorizer.ActionKeyPackageClaim, "", map[string]any{
		authorizer.FieldPerson: person, authorizer.FieldConversation: conversation,
	}); err != nil {
		return nil, err
	}
	d, err := s.directory(ctx, person)
	if err != nil {
		return nil, err
	}
	var out []Claimed
	for _, r := range d.Devices() {
		kp, err := s.store.ClaimKeyPackage(ctx, person, r.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Claimed{Device: r.ID, KeyPackage: kp.Data})
	}
	return out, nil
}

func (s *Service) conversation(ctx context.Context, id string) (store.Conversation, error) {
	c, err := s.store.Conversation(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return c, apierr.New(apierr.CodeNotFound, "no such conversation")
	}
	return c, err
}

// leafOf is the calling device's credential as a leaf names it.
func leafOf(w Who) string { return messaging.Identity{Person: w.Person, Device: w.Device}.String() }

// Create creates a conversation from its creator's group info of epoch
// 0, with its ratchet tree.
func (s *Service) Create(ctx context.Context, w Who, id string, groupInfo []byte) (*store.Conversation, error) {
	if _, err := messaging.LatereIdentity(id); err != nil {
		return nil, apierr.New(apierr.CodeInvalid, "a conversation id is 1 to 128 of A-Z, a-z, 0-9, '.', '_', '~' and '-'")
	}
	view, err := mls.NewPublicGroup(groupInfo, mls.JoinOptions{}, messaging.Config())
	if err != nil {
		return nil, apierr.Wrap(apierr.CodeInvalid, err)
	}
	if err := messaging.CheckSuite(view.CipherSuite()); err != nil {
		return nil, apierr.Wrap(apierr.CodeInvalid, err)
	}
	st, err := messaging.ParseState(view.Extensions())
	if err != nil {
		return nil, apierr.Wrap(apierr.CodeInvalid, err)
	}
	want := messaging.State{Kind: st.Kind, Level: messaging.LevelOff, People: []string{w.Person}, Owners: []string{w.Person}}
	opts, err := messaging.CreateOptions(want, s.ExternalSender())
	if err != nil {
		return nil, apierr.Wrap(apierr.CodeInvalid, err)
	}
	members := view.Members()
	switch {
	case !bytes.Equal(view.GroupID(), messaging.GroupID(id)):
		return nil, apierr.New(apierr.CodeInvalid, "the group's id is not the conversation's")
	case view.Epoch() != 0:
		return nil, apierr.New(apierr.CodeInvalid, "a conversation starts at epoch 0")
	case len(members) != 1 || string(members[0].Credential.Identity) != leafOf(w):
		return nil, apierr.New(apierr.CodeInvalid, "a conversation starts with the calling device alone")
	case !st.Equal(want):
		return nil, apierr.New(apierr.CodeInvalid, "a conversation starts with its creator as its one person and owner, and Off")
	case !sameExtensions(view.Extensions(), opts.Extensions):
		return nil, apierr.New(apierr.CodeInvalid, "the group's extensions are not the profile's with this server as its external sender")
	}
	d, err := s.directory(ctx, w.Person)
	if err != nil {
		return nil, err
	}
	if err := d.CheckMember(members[0]); err != nil {
		return nil, apierr.Wrap(apierr.CodeInvalid, err)
	}
	c := store.Conversation{ID: id, Kind: st.Kind, Level: st.Level, People: st.People, Owners: st.Owners, GroupInfo: groupInfo,
		Members: []store.Member{{Person: w.Person, Device: w.Device}}}
	if err := s.ask(ctx, w, authorizer.ActionConversationCreate, id, facts(&c, nil)); err != nil {
		return nil, err
	}
	if c.View, err = view.MarshalBinary(); err != nil {
		return nil, err
	}
	if err := s.store.CreateConversation(ctx, c); err != nil {
		if errors.Is(err, store.ErrExists) {
			return nil, apierr.New(apierr.CodeExists, "the conversation id is taken")
		}
		return nil, err
	}
	return &c, nil
}

func sameExtensions(a, b []mls.Extension) bool {
	return slices.EqualFunc(a, b, func(x, y mls.Extension) bool { return x.Type == y.Type && bytes.Equal(x.Data, y.Data) })
}

// Get reads a conversation the caller is one of the people of.
func (s *Service) Get(ctx context.Context, w Who, id string) (*store.Conversation, error) {
	c, err := s.conversation(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.ask(ctx, w, authorizer.ActionConversationRead, id, facts(&c, nil)); err != nil {
		return nil, err
	}
	return &c, nil
}

// List lists the caller's conversations.
func (s *Service) List(ctx context.Context, w Who, after string, limit int) ([]store.Conversation, error) {
	if err := s.ask(ctx, w, authorizer.ActionConversationList, "", map[string]any{authorizer.FieldPerson: w.Person}); err != nil {
		return nil, err
	}
	return s.store.Conversations(ctx, w.Person, after, clampLimit(limit))
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return DefaultListLimit
	}
	return min(limit, MaxListLimit)
}

// Membership answers whether a person is one of a conversation's people
// now, for a storage service deciding a read of a file sent there.
func (s *Service) Membership(ctx context.Context, w Who, id, person string) (bool, error) {
	c, err := s.conversation(ctx, id)
	if err != nil {
		return false, err
	}
	if err := s.ask(ctx, w, authorizer.ActionConversationMembership, id, facts(&c, map[string]any{authorizer.FieldPerson: person})); err != nil {
		return false, err
	}
	return c.Has(person), nil
}

// hub wakes the reads that wait on a conversation's next message. It is
// in the process: a read waits on the replica its message arrives at.
type hub struct {
	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

func (h *hub) wait(id string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan struct{})
	h.waiters[id] = append(h.waiters[id], ch)
	return ch
}

func (h *hub) wake(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.waiters[id] {
		close(ch)
	}
	delete(h.waiters, id)
}

func (h *hub) forget(id string, ch chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.waiters[id] = slices.DeleteFunc(h.waiters[id], func(c chan struct{}) bool { return c == ch })
	if len(h.waiters[id]) == 0 {
		delete(h.waiters, id)
	}
}
