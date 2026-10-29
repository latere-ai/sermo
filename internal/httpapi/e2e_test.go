// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit/issuertest"
	"latere.ai/x/sdk-go/messaging"
	"latere.ai/x/sdk-go/mls"

	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/conv"
	"latere.ai/x/sermo/internal/httpapi"
	"latere.ai/x/sermo/internal/store"
	"latere.ai/x/sermo/internal/store/memory"
)

// env is sermod on the in-memory store, with an issuer of tokens, and a
// record of every response body and log line, which the canary checks
// read.
type env struct {
	t      *testing.T
	srv    *httptest.Server
	issuer *issuertest.Server
	mu     sync.Mutex
	seen   bytes.Buffer
	logs   *syncBuffer
	svc    *conv.Service
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// option changes how newEnv builds sermod.
type option func(*options)

type options struct {
	authorizer access.Authorizer
	store      store.Store
	maxBytes   int64
	now        func() time.Time
}

func newEnv(t *testing.T, opts ...option) *env {
	t.Helper()
	o := options{authorizer: access.NewAuthorizer(access.MemberPolicy{}), store: memory.New(nil), maxBytes: 8 << 20} // the service's own clock
	for _, opt := range opts {
		opt(&o)
	}
	issuer := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := conv.New(conv.Options{Store: o.store, Authorizer: o.authorizer, ServiceKey: key, Now: o.now})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := access.NewVerifier([]string{issuer.URL()}, []string{"sermo"}, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	api, err := httpapi.New(httpapi.Options{Service: svc, Authenticator: verifier, MaxRequestBytes: o.maxBytes,
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, srv: httptest.NewServer(api), issuer: issuer, logs: logs, svc: svc}
	t.Cleanup(e.srv.Close)
	return e
}

// answer is a response: its status and, for an error, its code.
type answer struct {
	status int
	code   string
}

// call sends one request as a person, from a device when device is not
// empty, and decodes the answer into out.
func (e *env) call(method, path, token, device string, in, out any) answer {
	e.t.Helper()
	var body io.Reader
	switch v := in.(type) {
	case nil:
	case string:
		body = strings.NewReader(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			e.t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+httpapi.Prefix+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if device != "" {
		req.Header.Set(httpapi.DeviceHeader, device)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	e.mu.Lock()
	e.seen.Write(b)
	e.mu.Unlock()
	holdToDocument(e.t, method, path, resp.StatusCode, b)
	a := answer{status: resp.StatusCode}
	if resp.StatusCode >= 400 {
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(b, &env); err != nil || env.Error.Code == "" || env.Error.Message == "" {
			e.t.Fatalf("%s %s: %d with no error envelope: %s", method, path, resp.StatusCode, b)
		}
		a.code = env.Error.Code
		return a
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
	return a
}

// must fails the test unless a call answered status.
func (e *env) must(a answer, status int, what string) {
	e.t.Helper()
	if a.status != status {
		e.t.Fatalf("%s: answered %d %s, want %d", what, a.status, a.code, status)
	}
}

// device is one device of a person, as an app holds it.
type device struct {
	e      *env
	person string
	id     messaging.Identity
	token  string
	key    ed25519.PrivateKey
	enc    *ecdh.PrivateKey
	signer *mls.SignatureKey
	record messaging.DeviceRecord
	kps    map[string]keyPackage // by reference, hex
	group  *mls.Group
}

type keyPackage struct {
	kp      *mls.KeyPackage
	secrets *mls.KeyPackageSecrets
}

// newDevice makes a person's first device, registers it as a root and
// publishes key packages.
func (e *env) newDevice(person, name string) *device {
	e.t.Helper()
	d := e.register(person, name)
	d.publish(2)
	return d
}

// register makes a person's first device and registers it as a root.
func (e *env) register(person, name string) *device {
	e.t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	enc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	signer, err := mls.NewSignatureKey(messaging.Suite, key.Seed())
	if err != nil {
		e.t.Fatal(err)
	}
	id, err := messaging.DeviceIdentity(person, name)
	if err != nil {
		e.t.Fatal(err)
	}
	rec, err := messaging.NewDeviceRecord(person, name, key, enc.PublicKey(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	d := &device{e: e, person: person, id: id, token: e.issuer.Mint(issuertest.Claims{Sub: person}), key: key, enc: enc,
		signer: signer, record: rec, kps: map[string]keyPackage{}}
	e.must(e.call("PUT", "/devices/"+name, d.token, "", rec, nil), http.StatusNoContent, "register "+person)
	return d
}

// keyPackages makes n key packages of the device and keeps their
// secrets for its Welcomes.
func (d *device) keyPackages(n int) httpapi.KeyPackagesBody {
	d.e.t.Helper()
	var body httpapi.KeyPackagesBody
	for range n {
		kp, secrets, err := mls.NewKeyPackage(d.signer, d.id.Credential(), messaging.KeyPackageOptions())
		if err != nil {
			d.e.t.Fatal(err)
		}
		d.kps[hex.EncodeToString(kp.Ref())] = keyPackage{kp, secrets}
		body.KeyPackages = append(body.KeyPackages, kp.Bytes())
	}
	return body
}

func (d *device) publish(n int) {
	d.e.t.Helper()
	d.e.must(d.call("POST", "/key-packages", d.keyPackages(n), nil), http.StatusNoContent, "publish")
}

func (d *device) call(method, path string, in, out any) answer {
	d.e.t.Helper()
	return d.e.call(method, path, d.token, d.id.Device, in, out)
}

// policy is the device's policy over the directory Sermo serves.
func (d *device) policy() *messaging.Policy {
	return &messaging.Policy{Directory: func(person string) (*messaging.Directory, error) {
		var list httpapi.DeviceList
		if a := d.call("GET", "/people/"+person+"/devices", nil, &list); a.status != http.StatusOK {
			return nil, fmt.Errorf("directory of %s: %d %s", person, a.status, a.code)
		}
		dir, _ := messaging.NewDirectory(person, list.Records, list.Revocations, nil)
		return dir, nil
	}}
}

// withState is the group's extensions with its state replaced.
func withState(t *testing.T, g *mls.Group, s messaging.State) []mls.Extension {
	t.Helper()
	ext, err := s.Extension()
	if err != nil {
		t.Fatal(err)
	}
	var out []mls.Extension
	for _, e := range g.Extensions() {
		if e.Type == messaging.StateExtension {
			e = ext
		}
		out = append(out, e)
	}
	return out
}

// commit stages a commit, sends it, and merges it on an accepted answer.
func (d *device) commit(conversation string, opts mls.CommitOptions) (answer, httpapi.Sent) {
	d.e.t.Helper()
	sc, err := d.group.Commit(opts)
	if err != nil {
		d.e.t.Fatal(err)
	}
	if _, err := d.policy().CheckCommit(d.group, sc.Changes()); err != nil {
		d.e.t.Logf("the committer's own check refuses: %v", err)
	}
	var sent httpapi.Sent
	a := d.call("POST", "/conversations/"+conversation+"/messages", httpapi.SendBody{Message: sc.Message(), Welcome: sc.Welcome(), GroupInfo: sc.GroupInfo()}, &sent)
	if a.status == http.StatusCreated {
		if err := d.group.Merge(sc); err != nil {
			d.e.t.Fatal(err)
		}
	}
	return a, sent
}

// catchUp reads the log after a sequence number and processes each
// message with the device's group, checking and merging commits.
func (d *device) catchUp(conversation string, after int64) ([]messaging.Payload, int64) {
	d.e.t.Helper()
	var page httpapi.MessageList
	d.e.must(d.call("GET", fmt.Sprintf("/conversations/%s/messages?after=%d", conversation, after), nil, &page), http.StatusOK, "read")
	var got []messaging.Payload
	for _, m := range page.Messages {
		if m.Person == d.person && m.Device == d.id.Device {
			continue // its own
		}
		msg, err := d.group.Process(m.Message)
		if err != nil {
			d.e.t.Fatalf("%s processing seq %d: %v", d.id, m.Seq, err)
		}
		switch msg.Kind {
		case mls.MessageApplication:
			p, err := messaging.ParsePayload(msg.ApplicationData)
			if err != nil {
				d.e.t.Fatal(err)
			}
			got = append(got, p)
		case mls.MessageCommit:
			if _, err := d.policy().CheckCommit(d.group, msg.Commit.Changes()); err != nil {
				d.e.t.Fatalf("%s refuses seq %d: %v", d.id, m.Seq, err)
			}
			if err := d.group.Merge(msg.Commit); err != nil {
				d.e.t.Fatal(err)
			}
		}
	}
	return got, page.Next
}

// join takes the device's welcome and joins the group.
func (d *device) join(conversation string) messaging.HistoryRange {
	d.e.t.Helper()
	var list httpapi.WelcomeList
	d.e.must(d.call("GET", "/welcomes", nil, &list), http.StatusOK, "welcomes")
	if len(list.Welcomes) != 1 || list.Welcomes[0].Conversation != conversation {
		d.e.t.Fatalf("%s has welcomes %+v", d.id, list.Welcomes)
	}
	w := list.Welcomes[0]
	refs, err := mls.WelcomeKeyPackageRefs(w.Welcome)
	if err != nil {
		d.e.t.Fatal(err)
	}
	var kp keyPackage
	for _, r := range refs {
		if k, ok := d.kps[hex.EncodeToString(r)]; ok {
			kp = k
		}
	}
	if kp.kp == nil {
		d.e.t.Fatal("the Welcome is for no key package of the device's")
	}
	if d.group, err = d.policy().JoinGroup(w.Welcome, kp.kp, kp.secrets, d.signer, mls.JoinOptions{}); err != nil {
		d.e.t.Fatal(err)
	}
	n, err := messaging.ParseCommitNotice(w.Notice)
	if err != nil {
		d.e.t.Fatal(err)
	}
	jn, err := n.Open(d.group, kp.kp, kp.secrets)
	if err != nil {
		d.e.t.Fatal(err)
	}
	d.e.must(d.call("DELETE", "/welcomes/"+w.ID, nil, nil), http.StatusNoContent, "drop the welcome")
	return jn.Range
}

// seal is a text message from the device to its group.
func (d *device) seal(text string) []byte {
	d.e.t.Helper()
	b, err := messaging.EncodePayload(messaging.Payload{ID: messaging.NewConversationID(), SentAt: time.Now().UTC().Truncate(time.Millisecond),
		Type: messaging.PayloadText, Text: text})
	if err != nil {
		d.e.t.Fatal(err)
	}
	ct, err := d.group.Encrypt(b, nil)
	if err != nil {
		d.e.t.Fatal(err)
	}
	return ct
}

func (d *device) say(conversation, text string) httpapi.Sent {
	d.e.t.Helper()
	var sent httpapi.Sent
	d.e.must(d.call("POST", "/conversations/"+conversation+"/messages", httpapi.SendBody{Message: d.seal(text)}, &sent), http.StatusCreated, "say")
	return sent
}

// A conversation between people end to end: devices register, a group
// is created and a person let in, messages cross, the rules and the
// epochs refuse what they must, a revoked device is removed by Sermo's
// proposal, and nothing written to anyone or any key reaches a log line
// or a response.
func TestConversation(t *testing.T) {
	e := newEnv(t)
	const canary = "canary-7f3a9c the words no server reads"

	var service httpapi.Service
	e.must(e.call("GET", "/service", e.issuer.Mint(issuertest.Claims{Sub: "alice"}), "", nil, &service), http.StatusOK, "service")
	external := mls.ExternalSender{SignatureKey: service.ExternalSender.SignatureKey, Credential: mls.BasicCredential([]byte(service.ExternalSender.Identity))}

	alice, bob, carol := e.newDevice("alice", "phone"), e.newDevice("bob", "pixel"), e.newDevice("carol", "tablet")

	// alice creates a conversation.
	id := messaging.NewConversationID()
	state := messaging.State{Kind: messaging.KindGroup, People: []string{"alice"}, Owners: []string{"alice"}}
	opts, err := messaging.CreateOptions(state, external)
	if err != nil {
		t.Fatal(err)
	}
	if alice.group, err = mls.CreateGroup(messaging.GroupID(id), alice.signer, alice.id.Credential(), opts, alice.policy().Config()); err != nil {
		t.Fatal(err)
	}
	info, err := alice.group.GroupInfo(mls.GroupInfoOptions{RatchetTree: true, ExternalPub: true})
	if err != nil {
		t.Fatal(err)
	}
	if a := alice.call("POST", "/conversations", `{"id":"x","group_info":"","extra":1}`, nil); a.code != "unknown_field" {
		t.Fatalf("a member the API lacks: %+v", a)
	}
	bare, err := alice.group.GroupInfo(mls.GroupInfoOptions{RatchetTree: true})
	if err != nil {
		t.Fatal(err)
	}
	if a := alice.call("POST", "/conversations", httpapi.CreateBody{ID: id, GroupInfo: bare}, nil); a.code != "invalid" {
		t.Fatalf("a group info without the external key: %+v", a)
	}
	var created httpapi.Conversation
	e.must(alice.call("POST", "/conversations", httpapi.CreateBody{ID: id, GroupInfo: info}, &created), http.StatusCreated, "create")
	if created.ID != id || created.Epoch != 0 || len(created.People) != 1 {
		t.Fatalf("created %+v", created)
	}

	// alice lets bob in.
	var claimed httpapi.ClaimedList
	e.must(alice.call("POST", "/key-packages/claim", httpapi.ClaimBody{Person: "bob", Conversation: id}, &claimed), http.StatusOK, "claim")
	if len(claimed.KeyPackages) != 1 {
		t.Fatalf("claimed %+v", claimed)
	}
	bobKP, err := mls.ParseKeyPackage(claimed.KeyPackages[0].KeyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if who, err := messaging.CheckKeyPackage(bobKP); err != nil || who != bob.id {
		t.Fatalf("claimed a key package of %v: %v", who, err)
	}
	none := messaging.HistoryRange{Kind: messaging.RangeNone}
	ad, err := messaging.NewCommitNotice(alice.group, none, []messaging.Joiner{{KeyPackage: bobKP, Notice: messaging.JoinerNotice{Range: none}}})
	if err != nil {
		t.Fatal(err)
	}
	state.People = []string{"alice", "bob"}
	a, _ := alice.commit(id, mls.CommitOptions{Add: []*mls.KeyPackage{bobKP}, ReplaceExtensions: true, Extensions: withState(t, alice.group, state),
		AuthenticatedData: ad, WelcomeExtensions: []mls.Extension{messaging.WelcomeExtension(ad)}})
	e.must(a, http.StatusCreated, "let bob in")
	if rng := bob.join(id); rng.Kind != messaging.RangeNone {
		t.Fatalf("bob was told range %v", rng.Kind)
	}

	// Messages cross.
	sent := alice.say(id, canary)
	got, _ := bob.catchUp(id, 0)
	if len(got) != 1 || got[0].Text != canary {
		t.Fatalf("bob read %+v", got)
	}

	// A device speaks only for itself: bob names alice's phone, and then
	// a device no one has.
	for _, other := range []string{alice.id.Device, "watch"} {
		if a := e.call("GET", "/conversations/"+id+"/messages", bob.token, other, nil, nil); a.code != "not_your_device" {
			t.Fatalf("bob as device %s: %+v", other, a)
		}
	}
	if a := e.call("GET", "/conversations/"+id, "", "", nil, nil); a.code != "missing_token" {
		t.Fatalf("no token: %+v", a)
	}
	if a := e.call("GET", "/conversations/"+id, "not-a-token", "", nil, nil); a.code != "invalid_token" {
		t.Fatalf("a bad token: %+v", a)
	}
	if a := carol.call("GET", "/conversations/"+id+"/messages", nil, nil); a.code != "forbidden" {
		t.Fatalf("someone not of the conversation read it: %+v", a)
	}

	// One commit per epoch: bob's update wins epoch 1, and alice's commit
	// for it is taken.
	stale, err := alice.group.Commit(mls.CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	a, _ = bob.commit(id, mls.CommitOptions{})
	e.must(a, http.StatusCreated, "bob's update")
	if a := alice.call("POST", "/conversations/"+id+"/messages", httpapi.SendBody{Message: stale.Message(), GroupInfo: stale.GroupInfo()}, nil); a.code != "epoch_taken" {
		t.Fatalf("a commit for a taken epoch: %+v", a)
	}
	_, next := alice.catchUp(id, sent.Seq)
	if next <= sent.Seq {
		t.Fatal("alice read nothing after her message")
	}

	// The rules refuse bob, who is not an owner, letting carol in, and
	// the log does not change.
	var before httpapi.Conversation
	e.must(bob.call("GET", "/conversations/"+id, nil, &before), http.StatusOK, "read")
	e.must(carol.call("POST", "/key-packages/claim", httpapi.ClaimBody{Person: "carol", Conversation: id}, nil), http.StatusNotFound, "carol claims for a conversation not hers")
	carolKP := carol.kps[firstRef(carol)].kp
	state.People = []string{"alice", "bob", "carol"}
	ad, err = messaging.NewCommitNotice(bob.group, none, []messaging.Joiner{{KeyPackage: carolKP, Notice: messaging.JoinerNotice{Range: none}}})
	if err != nil {
		t.Fatal(err)
	}
	a, _ = bob.commit(id, mls.CommitOptions{Add: []*mls.KeyPackage{carolKP}, ReplaceExtensions: true, Extensions: withState(t, bob.group, state),
		AuthenticatedData: ad, WelcomeExtensions: []mls.Extension{messaging.WelcomeExtension(ad)}})
	if a.code != "refused" {
		t.Fatalf("a non-owner let someone in: %+v", a)
	}
	var after httpapi.Conversation
	e.must(bob.call("GET", "/conversations/"+id, nil, &after), http.StatusOK, "read")
	if after.Seq != before.Seq || after.Epoch != before.Epoch {
		t.Fatalf("a refused commit changed the log: %+v to %+v", before, after)
	}

	// bob revokes his phone; Sermo proposes its removal, and alice
	// commits it.
	v := messaging.Revocation{Person: "bob", Key: bob.record.SignatureKey}
	if err := v.Sign(bob.id.Device, bob.key); err != nil {
		t.Fatal(err)
	}
	e.must(bob.call("POST", "/revocations", v, nil), http.StatusNoContent, "revoke")
	e.must(e.call("POST", "/revocations", bob.token, "", v, nil), http.StatusNoContent, "revoke again, the removal proposed already")
	var page httpapi.MessageList
	e.must(alice.call("GET", fmt.Sprintf("/conversations/%s/messages?after=%d", id, next), nil, &page), http.StatusOK, "read")
	if len(page.Messages) != 1 || page.Messages[0].Kind != "proposal" || page.Messages[0].Person != "" {
		t.Fatalf("after the revocation the log holds %+v", page.Messages)
	}
	if m, err := alice.group.Process(page.Messages[0].Message); err != nil || m.Kind != mls.MessageProposal {
		t.Fatalf("alice takes Sermo's proposal: %v", err)
	}
	state.People = []string{"alice"}
	a, _ = alice.commit(id, mls.CommitOptions{IncludePending: true, ReplaceExtensions: true, Extensions: withState(t, alice.group, state)})
	e.must(a, http.StatusCreated, "commit the removal")
	if a := bob.call("GET", "/conversations/"+id, nil, nil); a.code != "not_your_device" {
		t.Fatalf("a revoked device: %+v", a)
	}

	// Nothing anyone wrote, and no private key, reached a response or a
	// log line.
	logs := e.logs.String()
	e.mu.Lock()
	seen := e.seen.String()
	e.mu.Unlock()
	for _, d := range []*device{alice, bob, carol} {
		for _, secret := range []string{string(d.key.Seed()), base64.StdEncoding.EncodeToString(d.key.Seed()), hex.EncodeToString(d.key.Seed()),
			base64.StdEncoding.EncodeToString(d.enc.Bytes())} {
			if strings.Contains(logs, secret) || strings.Contains(seen, secret) {
				t.Fatalf("a private key of %s left the device", d.id)
			}
		}
	}
	for _, s := range []string{canary, base64.StdEncoding.EncodeToString([]byte(canary))} {
		if strings.Contains(logs, s) || strings.Contains(seen, s) {
			t.Fatal("the plaintext of a message reached a log line or a response")
		}
	}
	if !strings.Contains(logs, "refused") {
		t.Fatal("the refusals were not logged")
	}
}

func firstRef(d *device) string {
	for ref := range d.kps {
		return ref
	}
	return ""
}
