// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"context"
	"math"
	"testing"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/access"
)

// The people of the policy's cases.
const (
	issuerURL = "https://issuer.example"
	me        = "person-a"
	them      = "person-b"
)

// ask is a question from me, with claims that carry no grants unless a
// case sets its own.
func ask(action, kind, id string, fields map[string]any) authz.Request {
	return authz.Request{
		Subject: authz.Subject(issuerURL, me), Issuer: issuerURL, Sub: me,
		Claims: map[string]any{"sub": me}, Action: action, Resource: authz.NewResource(kind, id, fields),
	}
}

// conversation is a question about a conversation of the people given,
// as sermod sends them in process.
func conversation(action string, people ...string) authz.Request {
	return ask(action, authorizer.KindConversation, "conv-1", map[string]any{authorizer.FieldPeople: people})
}

// of is a question about a record of a person's.
func of(action, kind, person string) authz.Request {
	return ask(action, kind, "", map[string]any{authorizer.FieldPerson: person})
}

// with is the request with claims replaced.
func with(req authz.Request, claims map[string]any) authz.Request {
	req.Claims = claims
	return req
}

// pat is the claims of a token minted from a personal access token that
// carries the authorization details given.
func pat(details any) map[string]any {
	return map[string]any{"sub": me, "token_use": authz.TokenUsePAT, "authorization_details": details}
}

// grant is one grant of the actions, qualified by Sermo's core.
func grant(id string, actions ...string) map[string]any {
	qualified := make([]any, len(actions))
	for i, a := range actions {
		qualified[i] = authorizer.Core + ":" + a
	}
	return map[string]any{"type": authz.GrantType, "actions": qualified, "identifier": id}
}

// TestMemberPolicy drives one case per row of the policy's doc comment,
// and the grants that narrow its allows.
func TestMemberPolicy(t *testing.T) {
	anonymous := conversation(authorizer.ActionConversationRead, me)
	anonymous.Subject, anonymous.Sub = "", ""
	noSub := conversation(authorizer.ActionConversationRead, me)
	noSub.Sub = ""
	probe := conversation(authorizer.ActionConversationRead, me)
	probe.Resource.ID = authz.ProbeID
	wrongKind := conversation(authorizer.ActionConversationRead, me)
	wrongKind.Resource.Kind = authorizer.KindDevice
	read := authorizer.ActionConversationRead

	cases := []struct {
		name   string
		req    authz.Request
		allow  bool
		reason string
	}{
		{"the probe id", probe, false, authz.ReasonProbe},
		{"no subject", anonymous, false, authz.ReasonAnonymous},
		{"no sub", noSub, false, authz.ReasonAnonymous},
		{"an action outside the vocabulary", conversation("conversation.delete", me), false, access.ReasonUnknownAction},
		{"an action about another kind", wrongKind, false, access.ReasonUnknownAction},

		{"a create of my own conversation", conversation(authorizer.ActionConversationCreate, me), true, ""},
		{"a create as it decodes from JSON", ask(authorizer.ActionConversationCreate, authorizer.KindConversation, "conv-1",
			map[string]any{authorizer.FieldPeople: []any{me}}), true, ""},
		{"a create with another person in it", conversation(authorizer.ActionConversationCreate, me, them), false, access.ReasonNotYours},
		{"a create of another's conversation", conversation(authorizer.ActionConversationCreate, them), false, access.ReasonNotYours},
		{"a create whose people are not strings", ask(authorizer.ActionConversationCreate, authorizer.KindConversation, "conv-1",
			map[string]any{authorizer.FieldPeople: []any{me, 7}}), false, access.ReasonNotYours},
		{"a create with no people", ask(authorizer.ActionConversationCreate, authorizer.KindConversation, "conv-1", nil), false, access.ReasonNotYours},

		{"a read of a conversation I am in", conversation(read, them, me), true, ""},
		{"a read as it decodes from JSON", ask(read, authorizer.KindConversation, "conv-1",
			map[string]any{authorizer.FieldPeople: []any{them, me}}), true, ""},
		{"a read of a conversation I am not in", conversation(read, them), false, access.ReasonNotMember},
		{"a read whose people are one string", ask(read, authorizer.KindConversation, "conv-1",
			map[string]any{authorizer.FieldPeople: me}), false, access.ReasonNotMember},
		{"a send to a conversation I am in", conversation(authorizer.ActionConversationSend, me, them), true, ""},
		{"a commit to a conversation I am not in", conversation(authorizer.ActionConversationCommit, them), false, access.ReasonNotMember},
		{"a leave of a conversation I am in", conversation(authorizer.ActionConversationLeave, me, them), true, ""},
		{"a membership question about a conversation I am in", conversation(authorizer.ActionConversationMembership, me, them), true, ""},
		{"a list of my conversations", of(authorizer.ActionConversationList, authorizer.KindConversation, me), true, ""},
		{"a list of another's conversations", of(authorizer.ActionConversationList, authorizer.KindConversation, them), false, access.ReasonNotYours},

		{"the assistant's read", conversation(authorizer.ActionConversationAssistantRead, me), false, access.ReasonNoAssistant},
		{"the assistant's post", conversation(authorizer.ActionConversationAssistantPost, me), false, access.ReasonNoAssistant},

		{"a list of another's devices", of(authorizer.ActionDeviceList, authorizer.KindDevice, them), true, ""},
		{"a claim of another's key packages", of(authorizer.ActionKeyPackageClaim, authorizer.KindKeyPackage, them), true, ""},

		{"a register of my device", of(authorizer.ActionDeviceRegister, authorizer.KindDevice, me), true, ""},
		{"a register of another's device", of(authorizer.ActionDeviceRegister, authorizer.KindDevice, them), false, access.ReasonNotYours},
		{"a vouch for my device", of(authorizer.ActionDeviceVouch, authorizer.KindDevice, me), true, ""},
		{"a delete of another's device", of(authorizer.ActionDeviceDelete, authorizer.KindDevice, them), false, access.ReasonNotYours},
		{"a publish of my key packages", of(authorizer.ActionKeyPackagePublish, authorizer.KindKeyPackage, me), true, ""},
		{"a publish of another's key packages", of(authorizer.ActionKeyPackagePublish, authorizer.KindKeyPackage, them), false, access.ReasonNotYours},
		{"my recovery record", of(authorizer.ActionBackupRecovery, authorizer.KindBackup, me), true, ""},
		{"another's recovery record", of(authorizer.ActionBackupRecovery, authorizer.KindBackup, them), false, access.ReasonNotYours},
		{"a record with no person", ask(authorizer.ActionBackupRecovery, authorizer.KindBackup, "", nil), false, access.ReasonNotYours},

		{"a grant that covers the read", with(conversation(read, me), pat([]any{grant("", read)})), true, ""},
		{"a grant on this conversation", with(conversation(read, me), pat([]any{grant("conv-1", read)})), true, ""},
		{"a grant on another conversation", with(conversation(read, me), pat([]any{grant("conv-2", read)})), false, authz.ReasonGrant},
		{"a grant of another action", with(conversation(read, me), pat([]any{grant("", authorizer.ActionConversationSend)})), false, authz.ReasonGrant},
		{"a token that names no grant", with(conversation(read, me), map[string]any{"sub": me, "token_use": authz.TokenUsePAT}), false, authz.ReasonGrant},
		{"a grant does not let me into another's conversation", with(conversation(read, them), pat([]any{grant("", read)})), false, access.ReasonNotMember},
		{"grants that are a string", with(conversation(read, me), pat("everything")), false, authz.ReasonGrant},
		{"a grant of another type", with(conversation(read, me), pat([]any{map[string]any{"type": "other", "actions": []any{"sermo:" + read}}})), false, authz.ReasonGrant},
		{"grants that do not encode", with(conversation(read, me), pat([]any{math.Inf(1)})), false, authz.ReasonGrant},
		{"grants on a token they do not narrow", with(conversation(read, me), map[string]any{"sub": me, "authorization_details": "everything"}), true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for name, decide := range map[string]func(context.Context, authz.Request) (authz.Decision, error){
				"Authorize": access.MemberPolicy{}.Authorize, "Decide": access.MemberPolicy{}.Decide,
			} {
				d, err := decide(context.Background(), c.req)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if d.Allow != c.allow || d.Reason != c.reason {
					t.Errorf("%s = allow %v, reason %q; want allow %v, reason %q", name, d.Allow, d.Reason, c.allow, c.reason)
				}
			}
		})
	}
}

// TestMemberPolicyAnswersEveryAction checks that no action of the
// vocabulary falls through to a deny for an unknown action, so a row
// added to the table without a rule here is found.
func TestMemberPolicyAnswersEveryAction(t *testing.T) {
	for _, action := range authorizer.Actions() {
		req := ask(action, authorizer.Kind(action), "conv-1", map[string]any{
			authorizer.FieldPeople: []string{me}, authorizer.FieldPerson: me,
		})
		d, err := access.MemberPolicy{}.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if d.Reason == access.ReasonUnknownAction {
			t.Errorf("%s: the policy does not know the action", action)
		}
	}
}
