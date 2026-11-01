// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit/issuertest"
	"latere.ai/x/pkg/authz"
	"latere.ai/x/sdk-go/messaging"
	"latere.ai/x/sdk-go/mls"

	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/conv"
	"latere.ai/x/sermo/internal/httpapi"
)

// vouched makes a device of voucher's person that voucher approves, and
// registers it.
func (e *env) vouched(voucher *device, name string) *device {
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
	id, err := messaging.DeviceIdentity(voucher.person, name)
	if err != nil {
		e.t.Fatal(err)
	}
	rec, err := messaging.NewDeviceRecord(voucher.person, name, key, enc.PublicKey(), &voucher.record)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := rec.Sign(voucher.key); err != nil {
		e.t.Fatal(err)
	}
	d := &device{e: e, person: voucher.person, id: id, token: voucher.token, key: key, enc: enc, signer: signer, record: rec,
		kps: map[string]keyPackage{}}
	e.must(e.call("PUT", "/devices/"+name, d.token, "", rec, nil), http.StatusNoContent, "register "+name)
	return d
}

// Records registered at once under one new id with different keys, each
// vouched for by the person's phone, leave one of them: the rest are
// refused as an id registered with other keys, rather than each passing
// its check on the same directory and the last write winning.
func TestRegistrationsOfOneIDAtOnce(t *testing.T) {
	e := newEnv(t)
	phone := e.newDevice("alice", "phone")
	const racers = 8
	records := make([]messaging.DeviceRecord, racers)
	for i := range records {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := messaging.NewDeviceRecord("alice", "tablet", key, enc.PublicKey(), &phone.record)
		if err != nil {
			t.Fatal(err)
		}
		if err := rec.Sign(phone.key); err != nil {
			t.Fatal(err)
		}
		records[i] = rec
	}
	answers := make([]answer, racers)
	var wg sync.WaitGroup
	for i, rec := range records {
		wg.Go(func() { answers[i] = e.call("PUT", "/devices/tablet", phone.token, "", rec, nil) })
	}
	wg.Wait()
	won, refused := -1, 0
	for i, a := range answers {
		switch {
		case a.status == http.StatusNoContent:
			won = i
		case a.code == "exists":
			refused++
		}
	}
	if won < 0 || refused != racers-1 {
		t.Fatalf("%d of %d registrations of one id were refused, want all but one: %+v", refused, racers, answers)
	}
	var list httpapi.DeviceList
	e.must(phone.call("GET", "/people/alice/devices", nil, &list), http.StatusOK, "list")
	tablets := 0
	for _, r := range list.Records {
		if r.ID == "tablet" {
			tablets++
			if !bytes.Equal(r.SignatureKey, records[won].SignatureKey) {
				t.Error("the tablet's record is not the registration that was answered 204")
			}
		}
	}
	if tablets != 1 {
		t.Errorf("alice has %d records named tablet, want 1", tablets)
	}
}

// A record registered again with the same keys, voucher and vouch is
// answered as registered and left as it is: what else it carries, a
// proof of possession no check looked at, does not replace the record
// the directory verified.
func TestRegisteredAgainIsLeftAsItIs(t *testing.T) {
	e := newEnv(t)
	phone := e.newDevice("alice", "phone")
	tablet := e.vouched(phone, "tablet")
	again := tablet.record
	again.Possession = bytes.Clone(again.Possession)
	again.Possession[0] ^= 0xff
	e.must(phone.call("PUT", "/devices/tablet", again, nil), http.StatusNoContent, "register again with another possession")
	var list httpapi.DeviceList
	e.must(phone.call("GET", "/people/alice/devices", nil, &list), http.StatusOK, "list")
	for _, r := range list.Records {
		if r.ID == "tablet" && !bytes.Equal(r.Possession, tablet.record.Possession) {
			t.Error("registering again replaced the tablet's record with one whose possession no check looked at")
		}
	}
	e.must(tablet.call("GET", "/key-packages", nil, nil), http.StatusOK, "the tablet still stands")
}

// A person's second device is approved by the first, takes the backup
// key it leaves, and is revoked; the recovery record is registered once.
func TestDevicesAndBackup(t *testing.T) {
	e := newEnv(t)
	phone := e.newDevice("alice", "phone")
	tablet := e.vouched(phone, "tablet")
	bob := e.newDevice("bob", "pixel")

	// Registering again is nothing new; other keys under the id, or a
	// record of someone else, are refused.
	e.must(phone.call("PUT", "/devices/tablet", tablet.record, nil), http.StatusNoContent, "register again")
	other := e.vouched(phone, "watch")
	clash := other.record
	clash.ID = "tablet"
	if a := phone.call("PUT", "/devices/tablet", clash, nil); a.code != "invalid" && a.code != "exists" {
		t.Fatalf("a record under a taken id: %+v", a)
	}
	if a := e.call("PUT", "/devices/pixel", phone.token, "", bob.record, nil); a.code != "invalid" {
		t.Fatalf("a record of another person: %+v", a)
	}
	var list httpapi.DeviceList
	e.must(bob.call("GET", "/people/alice/devices", nil, &list), http.StatusOK, "list")
	if len(list.Records) != 3 {
		t.Fatalf("alice has %d records", len(list.Records))
	}
	dir, _ := messaging.NewDirectory("alice", list.Records, list.Revocations, nil)

	// The recovery record, vouched for by the phone, with the backup key
	// wrapped under it.
	rk, err := messaging.NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := messaging.NewRecoveryRecord("alice", "recovery-1", rk, phone.record)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(phone.key); err != nil {
		t.Fatal(err)
	}
	wrapped := bytes.Repeat([]byte{0xA5}, 72) // opaque to the server
	if a := phone.call("PUT", "/recovery", httpapi.RecoveryBody{Record: rec}, nil); a.code != "invalid" {
		t.Fatalf("a recovery record without the wrapped key: %+v", a)
	}
	if a := phone.call("PUT", "/recovery", httpapi.RecoveryBody{Record: phone.record, Wrapped: wrapped}, nil); a.code != "invalid" {
		t.Fatalf("a device record as the recovery record: %+v", a)
	}
	e.must(phone.call("PUT", "/recovery", httpapi.RecoveryBody{Record: rec, Wrapped: wrapped}, nil), http.StatusNoContent, "recovery")
	var got httpapi.RecoveryBody
	e.must(phone.call("GET", "/recovery", nil, &got), http.StatusOK, "read the recovery")
	if got.Record.ID != "recovery-1" || !bytes.Equal(got.Wrapped, wrapped) {
		t.Fatalf("read back %+v", got)
	}
	second, err := messaging.NewRecoveryRecord("alice", "recovery-2", rk, phone.record)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Sign(phone.key); err != nil {
		t.Fatal(err)
	}
	if a := phone.call("PUT", "/recovery", httpapi.RecoveryBody{Record: second, Wrapped: wrapped}, nil); a.code != "exists" {
		t.Fatalf("a second recovery record while the first stands: %+v", a)
	}
	if a := bob.call("GET", "/recovery", nil, nil); a.code != "not_found" {
		t.Fatalf("bob's recovery: %+v", a)
	}

	// The phone leaves the backup key for the tablet, which takes it once.
	bk, err := messaging.NewBackupKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := bk.SealTo(tablet.record, phone.key)
	if err != nil {
		t.Fatal(err)
	}
	if a := phone.call("POST", "/devices/tablet/transfer", httpapi.TransferBody{}, nil); a.code != "invalid" {
		t.Fatalf("an empty transfer: %+v", a)
	}
	if a := phone.call("POST", "/devices/laptop/transfer", httpapi.TransferBody{Sealed: sealed}, nil); a.code != "not_found" {
		t.Fatalf("a transfer to no device: %+v", a)
	}
	e.must(phone.call("POST", "/devices/tablet/transfer", httpapi.TransferBody{Sealed: sealed}, nil), http.StatusNoContent, "leave")
	if a := phone.call("GET", "/devices/tablet/transfer", nil, nil); a.code != "forbidden" {
		t.Fatalf("the phone took the tablet's transfer: %+v", a)
	}
	var took httpapi.TransferBody
	e.must(tablet.call("GET", "/devices/tablet/transfer", nil, &took), http.StatusOK, "take")
	if opened, err := messaging.OpenBackupKey(tablet.enc, dir, tablet.record, took.Sealed); err != nil || !bytes.Equal(opened.Bytes(), bk.Bytes()) {
		t.Fatalf("the tablet opens what it took: %v", err)
	}
	if a := tablet.call("GET", "/devices/tablet/transfer", nil, nil); a.code != "not_found" {
		t.Fatalf("a transfer taken twice: %+v", a)
	}

	// Key packages: counted, and bounded per call.
	var count httpapi.KeyPackageCount
	e.must(phone.call("GET", "/key-packages", nil, &count), http.StatusOK, "count")
	if count.Count != 2 {
		t.Fatalf("the phone has %d key packages", count.Count)
	}
	// A last-resort key package, which a claim takes when the others
	// are gone, and the bound on what one device keeps.
	last := phone.keyPackages(1)
	e.must(phone.call("POST", "/key-packages", httpapi.KeyPackagesBody{LastResort: last.KeyPackages[0]}, nil), http.StatusNoContent, "last resort")
	e.must(phone.call("GET", "/key-packages", nil, &count), http.StatusOK, "count")
	if !count.LastResort {
		t.Fatal("the last-resort key package is not counted")
	}
	for i := 0; ; i++ {
		a := phone.call("POST", "/key-packages", phone.keyPackages(conv.MaxKeyPackagesPerCall), nil)
		if a.code == "too_large" {
			break
		}
		if a.status != http.StatusNoContent || i > conv.MaxKeyPackagesPerDevice/conv.MaxKeyPackagesPerCall {
			t.Fatalf("publishing past the bound on a device: %+v", a)
		}
	}
	tooMany := httpapi.KeyPackagesBody{KeyPackages: make([][]byte, conv.MaxKeyPackagesPerCall+1)}
	if a := phone.call("POST", "/key-packages", tooMany, nil); a.code != "too_large" {
		t.Fatalf("too many key packages: %+v", a)
	}
	if a := phone.call("POST", "/key-packages", httpapi.KeyPackagesBody{KeyPackages: [][]byte{[]byte("not a key package")}}, nil); a.code != "invalid" {
		t.Fatalf("a key package that does not parse: %+v", a)
	}

	// A record whose vouch does not verify, a key package of another
	// suite, and a last-resort key package that does not read.
	broken := e.vouched(phone, "pad").record
	broken.ID = "pen"
	if a := phone.call("PUT", "/devices/pen", broken, nil); a.code != "invalid" {
		t.Fatalf("a record whose signatures do not verify: %+v", a)
	}
	p256, err := mls.GenerateSignatureKey(mls.MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := mls.NewKeyPackage(p256, phone.id.Credential(), messaging.KeyPackageOptions())
	if err != nil {
		t.Fatal(err)
	}
	if a := phone.call("POST", "/key-packages", httpapi.KeyPackagesBody{KeyPackages: [][]byte{foreign.Bytes()}}, nil); a.code != "invalid" {
		t.Fatalf("a key package of another suite: %+v", a)
	}
	if a := phone.call("POST", "/key-packages", httpapi.KeyPackagesBody{LastResort: []byte("not a key package")}, nil); a.code != "invalid" {
		t.Fatalf("a last resort that does not read: %+v", a)
	}
	// A revocation is of a key of the caller's.
	if a := phone.call("POST", "/revocations", messaging.Revocation{Person: "bob", Key: bob.record.SignatureKey, By: "phone", Signature: []byte{1}}, nil); a.code != "invalid" {
		t.Fatalf("a revocation of another person's key: %+v", a)
	}
	// The tablet is approved again, by the watch: the same keys under a
	// new voucher, with the device's word for it.
	again, err := messaging.NewDeviceRecord("alice", "tablet", tablet.key, tablet.enc.PublicKey(), &other.record)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Sign(other.key); err != nil {
		t.Fatal(err)
	}
	e.must(phone.call("PUT", "/devices/tablet", again, nil), http.StatusNoContent, "vouch again")
	tablet.record = again

	// The recovery record revoked: the wrapped key is no longer served.
	gone := messaging.Revocation{Person: "alice", Key: rec.SignatureKey}
	if err := gone.Sign("phone", phone.key); err != nil {
		t.Fatal(err)
	}
	e.must(phone.call("POST", "/revocations", gone, nil), http.StatusNoContent, "revoke the recovery record")
	if a := phone.call("GET", "/recovery", nil, nil); a.code != "not_found" {
		t.Fatalf("a revoked recovery record: %+v", a)
	}

	// The phone revokes the tablet; the tablet no longer speaks, and
	// revoking it again changes nothing.
	v := messaging.Revocation{Person: "alice", Key: tablet.record.SignatureKey}
	if err := v.Sign("phone", phone.key); err != nil {
		t.Fatal(err)
	}
	forged := v
	forged.Signature = bytes.Clone(v.Signature)
	forged.Signature[0] ^= 1
	if a := phone.call("POST", "/revocations", forged, nil); a.code != "invalid" {
		t.Fatalf("a revocation that does not verify: %+v", a)
	}
	e.must(phone.call("POST", "/revocations", v, nil), http.StatusNoContent, "revoke")
	e.must(phone.call("POST", "/revocations", v, nil), http.StatusNoContent, "revoke again")
	if a := tablet.call("GET", "/key-packages", nil, nil); a.code != "not_your_device" {
		t.Fatalf("a revoked device: %+v", a)
	}
	if a := phone.call("PUT", "/devices/tablet", tablet.record, nil); a.code != "exists" {
		t.Fatalf("a revoked key registered again: %+v", a)
	}
	e.must(bob.call("GET", "/people/alice/devices", nil, &list), http.StatusOK, "list")
	if len(list.Revocations) != 2 { // the recovery record's and the tablet's
		t.Fatalf("alice has %d revocations", len(list.Revocations))
	}
}

// The reads around a conversation: the list, the group info, who is one
// of its people, paging through the log and waiting on it, a device
// joining on its own, a person leaving, and the sweep.
func TestConversationRoutes(t *testing.T) {
	// The clock stands still while the test runs, as a clock may, and
	// jumps two days for the sweep.
	now := time.Now()
	clock := func() time.Time { return now }
	e := newEnv(t, func(o *options) { o.now = clock })
	alice, bob, carol := e.newDevice("alice", "phone"), e.newDevice("bob", "pixel"), e.newDevice("carol", "tablet")
	external := service(t, e)

	second := create(t, alice, external)
	id := create(t, alice, external) // alice's group is this one's from here on
	var page httpapi.ConversationList
	e.must(alice.call("GET", "/conversations?limit=1", nil, &page), http.StatusOK, "list")
	if len(page.Conversations) != 1 || page.Next == "" {
		t.Fatalf("first page %+v", page)
	}
	e.must(alice.call("GET", "/conversations?limit=1&after="+page.Next, nil, &page), http.StatusOK, "list")
	if len(page.Conversations) != 1 || (page.Conversations[0].ID != id && page.Conversations[0].ID != second) {
		t.Fatalf("second page %+v", page)
	}
	if a := alice.call("GET", "/conversations?limit=100000", nil, nil); a.code != "invalid" {
		t.Fatalf("a limit past the most: %+v", a)
	}
	if a := alice.call("GET", "/conversations?limit=x", nil, nil); a.code != "invalid" {
		t.Fatalf("a limit that is not a number: %+v", a)
	}
	if a := alice.call("GET", "/conversations/nothing-here", nil, nil); a.code != "not_found" {
		t.Fatalf("a conversation that is not there: %+v", a)
	}
	if a := alice.call("POST", "/conversations", httpapi.CreateBody{ID: id, GroupInfo: groupInfo(t, alice)}, nil); a.code != "exists" && a.code != "invalid" {
		t.Fatalf("a conversation id taken: %+v", a)
	}

	letIn(t, alice, id, bob)
	var m httpapi.Membership
	e.must(alice.call("GET", "/conversations/"+id+"/people/bob", nil, &m), http.StatusOK, "membership")
	if !m.Member {
		t.Fatal("bob is not one of the people")
	}
	e.must(alice.call("GET", "/conversations/"+id+"/people/carol", nil, &m), http.StatusOK, "membership")
	if m.Member {
		t.Fatal("carol is one of the people")
	}
	if a := carol.call("GET", "/conversations/"+id, nil, nil); a.code != "forbidden" {
		t.Fatalf("someone not of the conversation read it: %+v", a)
	}
	if a := carol.call("GET", "/conversations/"+id+"/people/bob", nil, nil); a.code != "forbidden" {
		t.Fatalf("someone not of the conversation asked who is: %+v", a)
	}

	// Paging, and a read that waits for the next message.
	for i := range 3 {
		alice.say(id, fmt.Sprintf("message %d", i))
	}
	// A page holds what bob may read of the entries it spans, so the
	// commit that let him in, from the epoch before his, takes a place
	// but is not his to read.
	var log httpapi.MessageList
	read, after := 0, int64(0)
	for range 4 {
		e.must(bob.call("GET", fmt.Sprintf("/conversations/%s/messages?after=%d&limit=2", id, after), nil, &log), http.StatusOK, "page")
		if len(log.Messages) > 2 || log.Next < after {
			t.Fatalf("a page %+v after %d", log, after)
		}
		read += len(log.Messages)
		after = log.Next
	}
	if read != 3 {
		t.Fatalf("bob read %d of alice's three messages page by page", read)
	}
	_, last := bob.catchUp(id, 0)
	done := make(chan httpapi.MessageList, 1)
	go func() {
		var waited httpapi.MessageList
		bob.e.call("GET", fmt.Sprintf("/conversations/%s/messages?after=%d&wait=5", id, last), bob.token, bob.id.Device, nil, &waited)
		done <- waited
	}()
	time.Sleep(100 * time.Millisecond)
	alice.say(id, "while bob waits")
	select {
	case waited := <-done:
		if len(waited.Messages) != 1 {
			t.Fatalf("the wait returned %+v", waited)
		}
		last = waited.Next
	case <-time.After(4 * time.Second):
		t.Fatal("a waiting read did not wake on a new message")
	}
	// A read held by another replica sees the message too, though only
	// the replica it arrived at can wake its own reads.
	other := e.replica()
	go func() {
		var waited httpapi.MessageList
		other.call("GET", fmt.Sprintf("/conversations/%s/messages?after=%d&wait=5", id, last), bob.token, bob.id.Device, nil, &waited)
		done <- waited
	}()
	time.Sleep(100 * time.Millisecond)
	alice.say(id, "on the other replica")
	select {
	case waited := <-done:
		if len(waited.Messages) != 1 {
			t.Fatalf("the wait on the other replica returned %+v", waited)
		}
	case <-time.After(3 * conv.ReadRecheck):
		t.Fatal("a read on another replica did not see a new message")
	}
	// A read whose caller goes away while it waits ends with it.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s%s/conversations/%s/messages?after=%d&wait=5", e.srv.URL, httpapi.Prefix, id, last+1), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bob.token)
	req.Header.Set(httpapi.DeviceHeader, bob.id.Device)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("a read past its caller's deadline answered %d", resp.StatusCode)
	}
	cancel()
	// A wait with nothing new ends at its deadline, empty.
	var empty httpapi.MessageList
	e.must(bob.call("GET", fmt.Sprintf("/conversations/%s/messages?after=%d&wait=1", id, last+1), nil, &empty), http.StatusOK, "wait")
	if len(empty.Messages) != 0 {
		t.Fatalf("a wait with nothing new returned %+v", empty)
	}
	if a := bob.call("GET", "/conversations/"+id+"/messages?wait=-1", nil, nil); a.code != "invalid" {
		t.Fatalf("a negative wait: %+v", a)
	}
	_, last = bob.catchUp(id, last)

	// bob's tablet joins on its own from the group info Sermo holds, of
	// the conversation and no older than the epoch bob's phone hands it
	// over the pairing.
	tablet := e.vouched(bob, "tablet")
	var gi httpapi.GroupInfoBody
	e.must(tablet.call("GET", "/conversations/"+id+"/group-info", nil, &gi), http.StatusOK, "group info")
	g, msg, err := tablet.policy().JoinExternal(gi.GroupInfo, tablet.signer, tablet.id, id, bob.group.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	tablet.group = g
	e.must(tablet.call("POST", "/conversations/"+id+"/messages", httpapi.SendBody{Message: msg, GroupInfo: groupInfo(t, tablet)}, nil), http.StatusCreated, "join")
	_, last = alice.catchUp(id, 0)
	bob.catchUp(id, last-1)

	// bob proposes the removal of his own phone, as a person does to
	// leave, and the proposal waits in the log for a commit.
	leave, err := bob.group.ProposeRemove(leafOf(t, bob.group, bob.id), nil)
	if err != nil {
		t.Fatal(err)
	}
	var proposed httpapi.Sent
	e.must(bob.call("POST", "/conversations/"+id+"/messages", httpapi.SendBody{Message: leave}, &proposed), http.StatusCreated, "propose")
	if proposed.Kind != "proposal" {
		t.Fatalf("sent %+v", proposed)
	}
	if a := carol.call("POST", "/conversations/"+id+"/messages", httpapi.SendBody{Message: leave}, nil); a.code != "forbidden" {
		t.Fatalf("someone not of the conversation sent: %+v", a)
	}
	if a := alice.call("GET", "/conversations/"+id+"/group-info", nil, nil); a.status != http.StatusOK {
		t.Fatalf("the group info: %+v", a)
	}

	// The sweep drops what is past the retention.
	now = now.Add(48 * time.Hour)
	n, err := e.svc.Sweep(context.Background(), 24*time.Hour)
	if err != nil || n == 0 {
		t.Fatalf("swept %d, %v", n, err)
	}
	e.must(alice.call("GET", "/conversations/"+id+"/messages?after=0", nil, &log), http.StatusOK, "read after the sweep")
	if len(log.Messages) != 0 {
		t.Fatalf("%d messages survived the sweep", len(log.Messages))
	}
	if a := alice.call("DELETE", "/welcomes/nothing", nil, nil); a.code != "not_found" {
		t.Fatalf("deleting a welcome that is not there: %+v", a)
	}
}

// A Welcome for a conversation the device's person was removed from
// before they fetched it is not handed out.
func TestWelcomeAfterRemoval(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.newDevice("alice", "phone"), e.newDevice("bob", "pixel")
	id := create(t, alice, service(t, e))
	var claimed httpapi.ClaimedList
	e.must(alice.call("POST", "/key-packages/claim", httpapi.ClaimBody{Person: "bob", Conversation: id}, &claimed), http.StatusOK, "claim")
	kp, err := mls.ParseKeyPackage(claimed.KeyPackages[0].KeyPackage)
	if err != nil {
		t.Fatal(err)
	}
	s, err := messaging.ParseState(alice.group.Extensions())
	if err != nil {
		t.Fatal(err)
	}
	alone := s
	s.People = append(s.People, "bob")
	none := messaging.HistoryRange{Kind: messaging.RangeNone}
	ad, err := messaging.NewCommitNotice(alice.group, none, []messaging.Joiner{{KeyPackage: kp, Notice: messaging.JoinerNotice{Range: none}}})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := alice.commit(id, mls.CommitOptions{Add: []*mls.KeyPackage{kp}, ReplaceExtensions: true, Extensions: withState(t, alice.group, s),
		AuthenticatedData: ad, WelcomeExtensions: []mls.Extension{messaging.WelcomeExtension(ad)}})
	e.must(a, http.StatusCreated, "let bob in")
	a, _ = alice.commit(id, mls.CommitOptions{Remove: []uint32{leafOf(t, alice.group, bob.id)}, ReplaceExtensions: true,
		Extensions: withState(t, alice.group, alone)})
	e.must(a, http.StatusCreated, "remove bob")
	var list httpapi.WelcomeList
	e.must(bob.call("GET", "/welcomes", nil, &list), http.StatusOK, "welcomes")
	if len(list.Welcomes) != 0 {
		t.Fatalf("bob was handed %d Welcomes to a conversation he is not in", len(list.Welcomes))
	}
}

// A create answers the conversation as the store keeps it, with the
// times it was stamped with, and a read of it answers the same.
func TestCreateAnswersTheStoredConversation(t *testing.T) {
	e := newEnv(t)
	alice := e.newDevice("alice", "phone")
	external := service(t, e)
	id := messaging.NewConversationID()
	opts, err := messaging.CreateOptions(messaging.State{Kind: messaging.KindGroup, People: []string{"alice"}, Owners: []string{"alice"}}, external)
	if err != nil {
		t.Fatal(err)
	}
	if alice.group, err = mls.CreateGroup(messaging.GroupID(id), alice.signer, alice.id.Credential(), opts, alice.policy().Config()); err != nil {
		t.Fatal(err)
	}
	var created, read httpapi.Conversation
	e.must(alice.call("POST", "/conversations", httpapi.CreateBody{ID: id, GroupInfo: groupInfo(t, alice)}, &created), http.StatusCreated, "create")
	e.must(alice.call("GET", "/conversations/"+id, nil, &read), http.StatusOK, "read")
	if created.Created.IsZero() || created.Updated.IsZero() {
		t.Fatalf("the create answered the times %s and %s", created.Created, created.Updated)
	}
	if !created.Created.Equal(read.Created) || !created.Updated.Equal(read.Updated) {
		t.Fatalf("the create answered %s and %s, a read %s and %s", created.Created, created.Updated, read.Created, read.Updated)
	}
}

// What every request is held to before the service sees it.
func TestRequests(t *testing.T) {
	e := newEnv(t, func(o *options) { o.maxBytes = 1 << 10 })
	alice := e.newDevice("alice", "phone")
	if a := alice.call("POST", "/conversations", `{"id":"`+strings.Repeat("a", 2<<10)+`"}`, nil); a.code != "too_large" {
		t.Fatalf("a body past the limit: %+v", a)
	}
	if a := alice.call("POST", "/conversations", "{", nil); a.code != "invalid" {
		t.Fatalf("a body that is not JSON: %+v", a)
	}
	if a := alice.call("POST", "/conversations", `{"id":"a"} {"id":"b"}`, nil); a.code != "invalid" {
		t.Fatalf("two values in one body: %+v", a)
	}
	if a := e.call("POST", "/conversations", alice.token, "", httpapi.CreateBody{}, nil); a.code != "not_your_device" {
		t.Fatalf("a device route with no device: %+v", a)
	}
	expired := e.issuer.Mint(issuertest.Claims{Sub: "alice", Exp: time.Now().Add(-time.Hour).Unix()})
	if a := e.call("GET", "/conversations", expired, "", nil, nil); a.code != "invalid_token" {
		t.Fatalf("an expired token: %+v", a)
	}
	if _, err := httpapi.New(httpapi.Options{}); err == nil {
		t.Fatal("an API with no service")
	}
	if _, err := conv.New(conv.Options{}); err == nil {
		t.Fatal("a service with no store")
	}
}

// unavailable is an authorizer that gives no decision.
type unavailable struct{}

func (unavailable) Authorize(context.Context, access.Caller, *http.Request, string, authz.Resource) (access.Decision, error) {
	return access.Decision{}, access.ErrUnavailable
}

// When the authorizer gives no decision, the request fails as one to try
// again, and nothing is decided in its place.
func TestAuthorizerUnavailable(t *testing.T) {
	e := newEnv(t, func(o *options) { o.authorizer = unavailable{} })
	token := e.issuer.Mint(issuertest.Claims{Sub: "alice"})
	if a := e.call("GET", "/conversations", token, "", nil, nil); a.code != "authorizer_unavailable" {
		t.Fatalf("with no decision: %+v", a)
	}
}

// service is Sermo as each group names it.
func service(t *testing.T, e *env) mls.ExternalSender {
	t.Helper()
	var s httpapi.Service
	e.must(e.call("GET", "/service", e.issuer.Mint(issuertest.Claims{Sub: "alice"}), "", nil, &s), http.StatusOK, "service")
	return mls.ExternalSender{SignatureKey: s.ExternalSender.SignatureKey, Credential: mls.BasicCredential([]byte(s.ExternalSender.Identity))}
}

func groupInfo(t *testing.T, d *device) []byte {
	t.Helper()
	info, err := d.group.GroupInfo(mls.GroupInfoOptions{RatchetTree: true, ExternalPub: true})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// create starts a group conversation of d's person alone.
func create(t *testing.T, d *device, external mls.ExternalSender) string {
	t.Helper()
	id := messaging.NewConversationID()
	opts, err := messaging.CreateOptions(messaging.State{Kind: messaging.KindGroup, People: []string{d.person}, Owners: []string{d.person}}, external)
	if err != nil {
		t.Fatal(err)
	}
	if d.group, err = mls.CreateGroup(messaging.GroupID(id), d.signer, d.id.Credential(), opts, d.policy().Config()); err != nil {
		t.Fatal(err)
	}
	d.e.must(d.call("POST", "/conversations", httpapi.CreateBody{ID: id, GroupInfo: groupInfo(t, d)}, nil), http.StatusCreated, "create")
	return id
}

// letIn has owner add joiner's person, and joiner join from its Welcome.
func letIn(t *testing.T, owner *device, id string, joiner *device) {
	t.Helper()
	var claimed httpapi.ClaimedList
	owner.e.must(owner.call("POST", "/key-packages/claim", httpapi.ClaimBody{Person: joiner.person, Conversation: id}, &claimed), http.StatusOK, "claim")
	if len(claimed.KeyPackages) != 1 {
		t.Fatalf("claimed %+v", claimed)
	}
	kp, err := mls.ParseKeyPackage(claimed.KeyPackages[0].KeyPackage)
	if err != nil {
		t.Fatal(err)
	}
	s, err := messaging.ParseState(owner.group.Extensions())
	if err != nil {
		t.Fatal(err)
	}
	s.People = append(s.People, joiner.person)
	none := messaging.HistoryRange{Kind: messaging.RangeNone}
	ad, err := messaging.NewCommitNotice(owner.group, none, []messaging.Joiner{{KeyPackage: kp, Notice: messaging.JoinerNotice{Range: none}}})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := owner.commit(id, mls.CommitOptions{Add: []*mls.KeyPackage{kp}, ReplaceExtensions: true, Extensions: withState(t, owner.group, s),
		AuthenticatedData: ad, WelcomeExtensions: []mls.Extension{messaging.WelcomeExtension(ad)}})
	owner.e.must(a, http.StatusCreated, "let in")
	joiner.join(id)
}

func leafOf(t *testing.T, g *mls.Group, id messaging.Identity) uint32 {
	t.Helper()
	for _, m := range g.Members() {
		if string(m.Credential.Identity) == id.String() {
			return m.Leaf
		}
	}
	t.Fatalf("%s has no leaf", id)
	return 0
}

// A list asked for with a limit of 0 pages as the default page does, so
// a client paging that way reaches every conversation.
func TestListPagesAtTheDefaultLimit(t *testing.T) {
	e := newEnv(t)
	alice := e.newDevice("alice", "phone")
	external := service(t, e)
	for range conv.DefaultListLimit + 1 {
		create(t, alice, external)
	}
	for _, q := range []string{"", "?limit=0"} {
		var first httpapi.ConversationList
		e.must(alice.call("GET", "/conversations"+q, nil, &first), http.StatusOK, "list "+q)
		if len(first.Conversations) != conv.DefaultListLimit || first.Next == "" {
			t.Fatalf("list %q: %d conversations, next %q", q, len(first.Conversations), first.Next)
		}
		var rest httpapi.ConversationList
		e.must(alice.call("GET", "/conversations?after="+first.Next+strings.Replace(q, "?", "&", 1), nil, &rest), http.StatusOK, "the next page "+q)
		if len(rest.Conversations) != 1 || rest.Next != "" {
			t.Fatalf("the page after, %q: %d conversations, next %q", q, len(rest.Conversations), rest.Next)
		}
	}
}
