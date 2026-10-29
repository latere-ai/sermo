// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"latere.ai/x/sdk-go/messaging"
	"latere.ai/x/sdk-go/mls"

	"latere.ai/x/sermo/internal/httpapi"
)

// A conversation starts only from a group of the calling device alone,
// in the profile, with this server as its external sender.
func TestCreateRefusals(t *testing.T) {
	e := newEnv(t)
	alice := e.newDevice("alice", "phone")
	tablet := e.vouched(alice, "tablet")
	external := service(t, e)

	group := func(d *device, s messaging.State, sender mls.ExternalSender, id string) []byte {
		t.Helper()
		opts, err := messaging.CreateOptions(s, sender)
		if err != nil {
			t.Fatal(err)
		}
		g, err := mls.CreateGroup(messaging.GroupID(id), d.signer, d.id.Credential(), opts, messaging.Config())
		if err != nil {
			t.Fatal(err)
		}
		d.group = g
		return groupInfo(t, d)
	}
	alone := messaging.State{Kind: messaging.KindGroup, People: []string{"alice"}, Owners: []string{"alice"}}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := mls.NewSignatureKey(messaging.Suite, otherKey.Seed())
	if err != nil {
		t.Fatal(err)
	}
	stranger := mls.ExternalSender{SignatureKey: otherSigner.PublicKey(), Credential: external.Credential}
	id := messaging.NewConversationID()
	for name, body := range map[string]httpapi.CreateBody{
		"an id out of the alphabet": {ID: "not an id!", GroupInfo: group(alice, alone, external, "x")},
		"no group info":             {ID: id, GroupInfo: []byte("not a group info")},
		"another group's id":        {ID: id, GroupInfo: group(alice, alone, external, messaging.NewConversationID())},
		"another device's leaf":     {ID: id, GroupInfo: group(tablet, alone, external, id)},
		"two people": {ID: id, GroupInfo: group(alice, messaging.State{Kind: messaging.KindGroup, People: []string{"alice", "bob"},
			Owners: []string{"alice"}}, external, id)},
		"another external sender": {ID: id, GroupInfo: group(alice, alone, stranger, id)},
		"a level other than Off": {ID: id, GroupInfo: group(alice, messaging.State{Kind: messaging.KindGroup, Level: messaging.LevelReadsAlong,
			People: []string{"alice"}, Owners: []string{"alice"}}, external, id)},
		"no state": func() httpapi.CreateBody {
			g, err := mls.CreateGroup(messaging.GroupID(id), alice.signer, alice.id.Credential(), mls.CreateOptions{}, messaging.Config())
			if err != nil {
				t.Fatal(err)
			}
			alice.group = g
			return httpapi.CreateBody{ID: id, GroupInfo: groupInfo(t, alice)}
		}(),
		"past its first epoch": func() httpapi.CreateBody {
			group(alice, alone, external, id)
			sc, err := alice.group.Commit(mls.CommitOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := alice.group.Merge(sc); err != nil {
				t.Fatal(err)
			}
			return httpapi.CreateBody{ID: id, GroupInfo: groupInfo(t, alice)}
		}(),
		"alice's leaf with another key": func() httpapi.CreateBody {
			impostor := *alice
			impostor.signer = otherSigner
			return httpapi.CreateBody{ID: id, GroupInfo: group(&impostor, alone, external, id)}
		}(),
	} {
		if a := alice.call("POST", "/conversations", body, nil); a.code != "invalid" {
			t.Errorf("%s: %+v", name, a)
		}
	}
}

// What the log refuses: messages that are not the conversation's, from
// a device other than the sender, of an epoch gone, and commits whose
// Welcome or group info does not match what they do.
func TestSendRefusals(t *testing.T) {
	e := newEnv(t)
	alice, bob, carol := e.newDevice("alice", "phone"), e.newDevice("bob", "pixel"), e.newDevice("carol", "tablet")
	external := service(t, e)
	id := create(t, alice, external)
	create(t, carol, external) // carol's own group, whose message is not this conversation's
	letIn(t, alice, id, bob)
	tablet := e.vouched(alice, "tablet") // alice's, not in the group

	post := func(d *device, body httpapi.SendBody) answer {
		t.Helper()
		return d.call("POST", "/conversations/"+id+"/messages", body, nil)
	}
	carolsMessage := carol.seal("for another conversation")
	for name, c := range map[string]struct {
		d    *device
		body httpapi.SendBody
		code string
	}{
		"nothing":                 {alice, httpapi.SendBody{}, "too_large"},
		"not a message":           {alice, httpapi.SendBody{Message: []byte("not a message")}, "invalid"},
		"another group's":         {alice, httpapi.SendBody{Message: carolsMessage}, "invalid"},
		"from a device not in it": {tablet, httpapi.SendBody{Message: alice.seal("as the tablet")}, "forbidden"},
	} {
		if a := post(c.d, c.body); a.code != c.code {
			t.Errorf("%s: %+v, want %s", name, a, c.code)
		}
	}

	// A commit of alice's phone, sent as her tablet, is not the tablet's.
	sc, err := alice.group.Commit(mls.CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a := post(tablet, httpapi.SendBody{Message: sc.Message(), GroupInfo: sc.GroupInfo()}); a.code != "refused" {
		t.Errorf("a commit sent by another device: %+v", a)
	}
	// A group info is not a message, and a commit whose signature was
	// changed does not verify.
	if a := post(alice, httpapi.SendBody{Message: groupInfo(t, alice)}); a.code != "invalid" {
		t.Errorf("a group info as a message: %+v", a)
	}
	// The last 33 bytes are the membership tag, which only members can
	// check; the 64 before them, the signature, which Sermo checks.
	tampered := append([]byte{}, sc.Message()...)
	tampered[len(tampered)-33-10] ^= 1
	if a := post(alice, httpapi.SendBody{Message: tampered, GroupInfo: sc.GroupInfo()}); a.code != "refused" && a.code != "invalid" {
		t.Errorf("a tampered commit: %+v", a)
	}
	// bob, who is not an owner, proposes removing alice, from a copy of
	// his group so that his own keeps no proposal pending.
	state, err := bob.group.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	copied, err := mls.UnmarshalGroup(state, messaging.Config())
	if err != nil {
		t.Fatal(err)
	}
	oust, err := copied.ProposeRemove(leafOf(t, copied, alice.id), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := post(bob, httpapi.SendBody{Message: oust}); a.code != "refused" {
		t.Errorf("a person not an owner proposed removing another: %+v", a)
	}
	// alice, the owner, may propose removing bob; the proposal waits in
	// the log for a commit, and is dropped here, from a copy again.
	state, err = alice.group.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if copied, err = mls.UnmarshalGroup(state, messaging.Config()); err != nil {
		t.Fatal(err)
	}
	remove, err := copied.ProposeRemove(leafOf(t, copied, bob.id), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := post(alice, httpapi.SendBody{Message: remove}); a.status != http.StatusCreated {
		t.Errorf("the owner proposed removing bob: %+v", a)
	}
	// A commit's group info that leaves out the external public key, from
	// a copy of alice's group that merges the commit it stages.
	state, err = alice.group.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if copied, err = mls.UnmarshalGroup(state, messaging.Config()); err != nil {
		t.Fatal(err)
	}
	bare, err := copied.Commit(mls.CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := copied.Merge(bare); err != nil {
		t.Fatal(err)
	}
	treeOnly, err := copied.GroupInfo(mls.GroupInfoOptions{RatchetTree: true})
	if err != nil {
		t.Fatal(err)
	}
	if a := post(alice, httpapi.SendBody{Message: bare.Message(), GroupInfo: treeOnly}); a.code != "invalid" {
		t.Errorf("a commit's group info without the external key: %+v", a)
	}
	// The group info of the epoch the commit leaves, or a Welcome for a
	// commit that adds no one.
	if a := post(alice, httpapi.SendBody{Message: sc.Message(), GroupInfo: groupInfo(t, alice)}); a.code != "invalid" {
		t.Errorf("a stale group info: %+v", a)
	}
	if a := post(alice, httpapi.SendBody{Message: sc.Message(), GroupInfo: sc.GroupInfo(), Welcome: []byte("a Welcome")}); a.code != "invalid" {
		t.Errorf("a Welcome for no one: %+v", a)
	}

	// bob's message of this epoch arrives after alice's commit moved on.
	late := bob.seal("written before the commit")
	if a, _ := alice.commit(id, mls.CommitOptions{}); a.status != http.StatusCreated {
		t.Fatalf("alice's update: %+v", a)
	}
	if a := post(bob, httpapi.SendBody{Message: late}); a.code != "wrong_epoch" {
		t.Errorf("a message of an epoch gone: %+v", a)
	}

	// A commit that adds carol carries her Welcome.
	var claimed httpapi.ClaimedList
	e.must(alice.call("POST", "/key-packages/claim", httpapi.ClaimBody{Person: "carol", Conversation: id}, &claimed), http.StatusOK, "claim")
	kp, err := mls.ParseKeyPackage(claimed.KeyPackages[0].KeyPackage)
	if err != nil {
		t.Fatal(err)
	}
	s, err := messaging.ParseState(alice.group.Extensions())
	if err != nil {
		t.Fatal(err)
	}
	s.People = append(s.People, "carol")
	none := messaging.HistoryRange{Kind: messaging.RangeNone}
	ad, err := messaging.NewCommitNotice(alice.group, none, []messaging.Joiner{{KeyPackage: kp, Notice: messaging.JoinerNotice{Range: none}}})
	if err != nil {
		t.Fatal(err)
	}
	add, err := alice.group.Commit(mls.CommitOptions{Add: []*mls.KeyPackage{kp}, ReplaceExtensions: true, Extensions: withState(t, alice.group, s),
		AuthenticatedData: ad, WelcomeExtensions: []mls.Extension{messaging.WelcomeExtension(ad)}})
	if err != nil {
		t.Fatal(err)
	}
	for name, welcome := range map[string][]byte{"without its Welcome": nil, "with a Welcome that does not read": []byte("not a Welcome")} {
		if a := post(alice, httpapi.SendBody{Message: add.Message(), GroupInfo: add.GroupInfo(), Welcome: welcome}); a.code != "invalid" {
			t.Errorf("an add %s: %+v", name, a)
		}
	}

	// Key packages: another device's, and a claim for a conversation
	// that is not there.
	if a := alice.call("POST", "/key-packages", bob.keyPackages(1), nil); a.code != "invalid" {
		t.Errorf("bob's key package published by alice: %+v", a)
	}
	if a := alice.call("POST", "/key-packages/claim", httpapi.ClaimBody{Person: "bob", Conversation: "nothing-here"}, nil); a.code != "not_found" {
		t.Errorf("a claim for no conversation: %+v", a)
	}
}
