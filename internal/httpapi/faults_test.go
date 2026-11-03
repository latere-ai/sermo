// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit/issuertest"
	"latere.ai/x/pkg/authz"
	"latere.ai/x/sdk-go/messaging"
	"latere.ai/x/sdk-go/mls"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/httpapi"
	"latere.ai/x/sermo/internal/store"
	"latere.ai/x/sermo/internal/store/memory"
)

var errInjected = errors.New("the store failed, as the test asked")

// faults is a store that fails the call a countdown reaches, and passes
// every other call to the store in memory.
type faults struct {
	inner store.Store
	mu    sync.Mutex
	left  int
	fired bool
}

// arm makes the n-th call from now fail; zero fails none.
func (f *faults) arm(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.left, f.fired = n, false
}

// didFire reports whether the armed call failed since arm.
func (f *faults) didFire() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fired
}

func (f *faults) tick() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.left == 0 {
		return nil
	}
	f.left--
	if f.left == 0 {
		f.fired = true
		return errInjected
	}
	return nil
}

func (f *faults) PutDevice(ctx context.Context, r messaging.DeviceRecord, check store.DirectoryCheck) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.inner.PutDevice(ctx, r, check)
}

func (f *faults) Devices(ctx context.Context, person string) ([]messaging.DeviceRecord, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.inner.Devices(ctx, person)
}

func (f *faults) AddRevocation(ctx context.Context, v messaging.Revocation, device string, check store.DirectoryCheck) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.inner.AddRevocation(ctx, v, device, check)
}

func (f *faults) Revocations(ctx context.Context, person string) ([]messaging.Revocation, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.inner.Revocations(ctx, person)
}

func (f *faults) PutRecovery(ctx context.Context, person string, wrapped []byte) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.inner.PutRecovery(ctx, person, wrapped)
}

func (f *faults) Recovery(ctx context.Context, person string) ([]byte, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.inner.Recovery(ctx, person)
}

func (f *faults) PutTransfer(ctx context.Context, person, device string, sealed []byte) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.inner.PutTransfer(ctx, person, device, sealed)
}

func (f *faults) TakeTransfer(ctx context.Context, person, device string) ([]byte, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.inner.TakeTransfer(ctx, person, device)
}

func (f *faults) AddKeyPackages(ctx context.Context, kps []store.KeyPackage) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.inner.AddKeyPackages(ctx, kps)
}

func (f *faults) CountKeyPackages(ctx context.Context, person, device string) (int, bool, error) {
	if err := f.tick(); err != nil {
		return 0, false, err
	}
	return f.inner.CountKeyPackages(ctx, person, device)
}

func (f *faults) ClaimKeyPackage(ctx context.Context, person, device string) (store.KeyPackage, error) {
	if err := f.tick(); err != nil {
		return store.KeyPackage{}, err
	}
	return f.inner.ClaimKeyPackage(ctx, person, device)
}

func (f *faults) CreateConversation(ctx context.Context, c store.Conversation) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.inner.CreateConversation(ctx, c)
}

func (f *faults) Conversation(ctx context.Context, id string) (store.Conversation, error) {
	if err := f.tick(); err != nil {
		return store.Conversation{}, err
	}
	return f.inner.Conversation(ctx, id)
}

func (f *faults) Conversations(ctx context.Context, person, after string, limit int) ([]store.Conversation, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.inner.Conversations(ctx, person, after, limit)
}

func (f *faults) Append(ctx context.Context, id string, version int64, a store.Append) (store.Message, error) {
	if err := f.tick(); err != nil {
		return store.Message{}, err
	}
	return f.inner.Append(ctx, id, version, a)
}

func (f *faults) Messages(ctx context.Context, id string, after int64, limit int) ([]store.Message, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.inner.Messages(ctx, id, after, limit)
}

func (f *faults) PutBackupRecords(ctx context.Context, person, conversation string, records []store.BackupRecord, limit int64) (int, error) {
	if err := f.tick(); err != nil {
		return 0, err
	}
	return f.inner.PutBackupRecords(ctx, person, conversation, records, limit)
}

func (f *faults) BackupRecords(ctx context.Context, person, conversation string, cursor int64, newest bool, limit int) ([]store.BackupRecord, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.inner.BackupRecords(ctx, person, conversation, cursor, newest, limit)
}

func (f *faults) Welcomes(ctx context.Context, person, device string) ([]store.Welcome, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.inner.Welcomes(ctx, person, device)
}

func (f *faults) DeleteWelcome(ctx context.Context, person, device, id string) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.inner.DeleteWelcome(ctx, person, device, id)
}

func (f *faults) DeleteMessagesBefore(ctx context.Context, before time.Time) (int, error) {
	if err := f.tick(); err != nil {
		return 0, err
	}
	return f.inner.DeleteMessagesBefore(ctx, before)
}

// Every request whose store fails answers internal and says nothing of
// the cause, whichever of its store calls fails, and the next try with
// the store well again goes through.
func TestStoreFaults(t *testing.T) {
	f := &faults{inner: memory.New(nil)}
	e := newEnv(t, func(o *options) { o.store = f })
	alice, bob := e.newDevice("alice", "phone"), e.newDevice("bob", "pixel")
	external := service(t, e)
	id := create(t, alice, external)
	letIn(t, alice, id, bob)
	tablet := e.vouched(alice, "tablet")

	bk, err := messaging.NewBackupKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := bk.SealTo(tablet.record, alice.key)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := messaging.NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := messaging.NewRecoveryRecord("alice", "recovery-1", rk, alice.record)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(alice.key); err != nil {
		t.Fatal(err)
	}
	v := messaging.Revocation{Person: "alice", Key: tablet.record.SignatureKey}
	if err := v.Sign("phone", alice.key); err != nil {
		t.Fatal(err)
	}

	requests := []struct {
		name string
		do   func() answer
	}{
		{"devices", func() answer { return bob.call("GET", "/people/alice/devices", nil, nil) }},
		{"register", func() answer { return e.call("PUT", "/devices/phone", alice.token, "", alice.record, nil) }},
		{"recovery", func() answer {
			return alice.call("PUT", "/recovery", httpapi.RecoveryBody{Record: rec, Wrapped: []byte("wrapped key, opaque here")}, nil)
		}},
		{"read the recovery", func() answer { return alice.call("GET", "/recovery", nil, nil) }},
		{"leave a transfer", func() answer {
			return alice.call("POST", "/devices/tablet/transfer", httpapi.TransferBody{Sealed: sealed}, nil)
		}},
		{"take it", func() answer { return tablet.call("GET", "/devices/tablet/transfer", nil, nil) }},
		{"count key packages", func() answer { return alice.call("GET", "/key-packages", nil, nil) }},
		{"claim", func() answer {
			return alice.call("POST", "/key-packages/claim", httpapi.ClaimBody{Person: "bob", Conversation: id}, nil)
		}},
		{"publish", func() answer { return alice.call("POST", "/key-packages", alice.keyPackages(1), nil) }},
		{"list", func() answer { return alice.call("GET", "/conversations", nil, nil) }},
		{"read", func() answer { return alice.call("GET", "/conversations/"+id, nil, nil) }},
		{"group info", func() answer { return alice.call("GET", "/conversations/"+id+"/group-info", nil, nil) }},
		{"membership", func() answer { return alice.call("GET", "/conversations/"+id+"/people/bob", nil, nil) }},
		{"messages", func() answer { return alice.call("GET", "/conversations/"+id+"/messages", nil, nil) }},
		{"welcomes", func() answer { return alice.call("GET", "/welcomes", nil, nil) }},
		{"store backup", func() answer {
			return alice.call("POST", "/conversations/"+id+"/backup", httpapi.BackupPut{Records: []httpapi.BackupRecord{{ID: "r1", Sealed: []byte("sealed, opaque here")}}}, nil)
		}},
		{"read backup", func() answer { return alice.call("GET", "/conversations/"+id+"/backup", nil, nil) }},
		{"say", func() answer {
			return alice.call("POST", "/conversations/"+id+"/messages", httpapi.SendBody{Message: alice.seal("through a failing store")}, nil)
		}},
		{"revoke", func() answer { return alice.call("POST", "/revocations", v, nil) }},
		{"create", func() answer {
			id := messaging.NewConversationID()
			opts, err := messaging.CreateOptions(messaging.State{Kind: messaging.KindGroup, People: []string{"alice"}, Owners: []string{"alice"}}, external)
			if err != nil {
				t.Fatal(err)
			}
			g, err := mls.CreateGroup(messaging.GroupID(id), alice.signer, alice.id.Credential(), opts, messaging.Config())
			if err != nil {
				t.Fatal(err)
			}
			info, err := g.GroupInfo(mls.GroupInfoOptions{RatchetTree: true, ExternalPub: true})
			if err != nil {
				t.Fatal(err)
			}
			return alice.call("POST", "/conversations", httpapi.CreateBody{ID: id, GroupInfo: info}, nil)
		}},
	}
	// Every store call a request makes fails in turn, until the request
	// makes fewer calls than the countdown, and each failure answers
	// internal, whatever the request would have answered had it gone on.
	for _, r := range requests {
		failed := 0
		for k := 1; k < 50; k++ {
			f.arm(k)
			a := r.do()
			fired := f.didFire()
			f.arm(0)
			if !fired {
				break
			}
			if a.code != "internal" {
				t.Errorf("%s with call %d failing: %+v", r.name, k, a)
			}
			failed++
		}
		if failed == 0 {
			t.Errorf("%s reached no store call", r.name)
		}
	}
	if strings.Contains(e.logs.String(), "opaque here") {
		t.Error("a request body reached a log line")
	}
	if !strings.Contains(e.logs.String(), errInjected.Error()) {
		t.Error("the store's failures were not logged")
	}
}

// denier refuses every request.
type denier struct{}

func (denier) Authorize(context.Context, access.Caller, *http.Request, string, authz.Resource) (access.Decision, error) {
	return access.Decision{Reason: "denied for the test"}, nil
}

// broken fails every decision with an error that is not an outage.
type broken struct{}

func (broken) Authorize(context.Context, access.Caller, *http.Request, string, authz.Resource) (access.Decision, error) {
	return access.Decision{}, errors.New("the authorizer broke")
}

// denyOnly denies one action and asks the member policy about the rest.
type denyOnly struct {
	action string
	inner  access.Authorizer
}

func (d denyOnly) Authorize(ctx context.Context, c access.Caller, r *http.Request, action string, res authz.Resource) (access.Decision, error) {
	if action == d.action {
		return access.Decision{Reason: "denied for the test"}, nil
	}
	return d.inner.Authorize(ctx, c, r, action, res)
}

// The authorizer decides creating, sending and committing after the
// rules pass, and a denial there keeps the log as it was.
func TestDeniedInConversation(t *testing.T) {
	member := access.NewAuthorizer(access.MemberPolicy{})
	for _, action := range []string{authorizer.ActionConversationCreate, authorizer.ActionConversationSend, authorizer.ActionConversationCommit,
		authorizer.ActionKeyPackagePublish, authorizer.ActionConversationLeave} {
		t.Run(action, func(t *testing.T) {
			e := newEnv(t, func(o *options) { o.authorizer = denyOnly{action, member} })
			alice := e.register("alice", "phone")
			if action == authorizer.ActionKeyPackagePublish {
				if a := alice.call("POST", "/key-packages", alice.keyPackages(1), nil); a.code != "forbidden" {
					t.Fatalf("publish: %+v", a)
				}
				return
			}
			external := service(t, e)
			id := messaging.NewConversationID()
			opts, err := messaging.CreateOptions(messaging.State{Kind: messaging.KindGroup, People: []string{"alice"}, Owners: []string{"alice"}}, external)
			if err != nil {
				t.Fatal(err)
			}
			if alice.group, err = mls.CreateGroup(messaging.GroupID(id), alice.signer, alice.id.Credential(), opts, alice.policy().Config()); err != nil {
				t.Fatal(err)
			}
			a := alice.call("POST", "/conversations", httpapi.CreateBody{ID: id, GroupInfo: groupInfo(t, alice)}, nil)
			if action == authorizer.ActionConversationCreate {
				if a.code != "forbidden" {
					t.Fatalf("create: %+v", a)
				}
				return
			}
			e.must(a, http.StatusCreated, "create")
			switch action {
			case authorizer.ActionConversationSend:
				a = alice.call("POST", "/conversations/"+id+"/messages", httpapi.SendBody{Message: alice.seal("denied")}, nil)
			case authorizer.ActionConversationLeave:
				leave, err := alice.group.ProposeRemove(leafOf(t, alice.group, alice.id), nil)
				if err != nil {
					t.Fatal(err)
				}
				a = alice.call("POST", "/conversations/"+id+"/messages", httpapi.SendBody{Message: leave}, nil)
			default:
				sc, err := alice.group.Commit(mls.CommitOptions{})
				if err != nil {
					t.Fatal(err)
				}
				a = alice.call("POST", "/conversations/"+id+"/messages", httpapi.SendBody{Message: sc.Message(), GroupInfo: sc.GroupInfo()}, nil)
			}
			if a.code != "forbidden" {
				t.Fatalf("%s: %+v", action, a)
			}
		})
	}
}

// The authorizer decides revoking, leaving the backup key and claiming
// key packages, each after the request reads.
func TestDeniedDevices(t *testing.T) {
	member := access.NewAuthorizer(access.MemberPolicy{})
	for _, action := range []string{authorizer.ActionDeviceDelete, authorizer.ActionDeviceVouch, authorizer.ActionKeyPackageClaim} {
		t.Run(action, func(t *testing.T) {
			e := newEnv(t, func(o *options) { o.authorizer = denyOnly{action, member} })
			phone := e.newDevice("alice", "phone")
			tablet := e.vouched(phone, "tablet")
			var answers []answer
			switch action {
			case authorizer.ActionDeviceDelete:
				v := messaging.Revocation{Person: "alice", Key: tablet.record.SignatureKey}
				if err := v.Sign("phone", phone.key); err != nil {
					t.Fatal(err)
				}
				answers = append(answers, phone.call("POST", "/revocations", v, nil))
			case authorizer.ActionDeviceVouch:
				answers = append(answers, phone.call("POST", "/devices/tablet/transfer", httpapi.TransferBody{Sealed: []byte("sealed")}, nil),
					tablet.call("GET", "/devices/tablet/transfer", nil, nil))
			case authorizer.ActionKeyPackageClaim:
				id := create(t, phone, service(t, e))
				answers = append(answers, phone.call("POST", "/key-packages/claim", httpapi.ClaimBody{Person: "alice", Conversation: id}, nil))
			}
			for i, a := range answers {
				if a.code != "forbidden" {
					t.Errorf("request %d: %+v", i, a)
				}
			}
		})
	}
}

// Every route asks the authorizer, and answers forbidden when it
// denies, or internal when it fails.
func TestDenied(t *testing.T) {
	for name, c := range map[string]struct {
		authorizer access.Authorizer
		code       string
	}{"denied": {denier{}, "forbidden"}, "broken": {broken{}, "internal"}} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(o *options) { o.authorizer = c.authorizer })
			token := e.issuer.Mint(issuertest.Claims{Sub: "alice"})
			for _, r := range []struct{ method, path string }{
				{"GET", "/people/bob/devices"},
				{"GET", "/recovery"},
				{"GET", "/conversations"},
				{"POST", "/key-packages/claim"},
			} {
				var body any
				if r.method == "POST" {
					body = httpapi.ClaimBody{Person: "bob", Conversation: "c1"}
				}
				if a := e.call(r.method, r.path, token, "", body, nil); a.code != c.code && a.code != "not_found" {
					t.Errorf("%s %s: %+v", r.method, r.path, a)
				}
			}
			if a := e.call("PUT", "/devices/phone", token, "", rootRecord(t, "alice", "phone"), nil); a.code != c.code {
				t.Errorf("register: %+v", a)
			}
		})
	}
}

// rootRecord is a fresh root record of person.
func rootRecord(t *testing.T, person, id string) messaging.DeviceRecord {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := messaging.NewDeviceRecord(person, id, key, enc.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
