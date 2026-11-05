// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"slices"
	"strings"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/sermo/authorizer"
)

// The reasons the member policy denies with beside the shared
// contract's probe, anonymous and grant.
const (
	ReasonUnknownAction = "unknown_action"
	ReasonNotMember     = "not_member"
	ReasonNotYours      = "not_yours"
	ReasonNoAssistant   = "no_assistant"
)

// MemberPolicy decides with SERMO_AUTHORIZER_URL unset. A person is the
// sub of the caller's token. Its rows:
//
//   - the probe id: deny, probe; no subject: deny, anonymous;
//   - an action outside the vocabulary, or about another kind: deny;
//   - a create of a conversation whose one person is the caller: allow;
//   - every other question about a conversation: allow when the caller
//     is one of its people, and a list of the caller's own;
//   - the assistant's reads and posts: deny, since only a plane in front
//     of Sermo knows who may speak as the assistant;
//   - listing a person's devices and claiming their key packages, which
//     adding them takes: allow;
//   - every other question about a device, a key package or a recovery
//     record: allow when it is the caller's own.
//
// It names no limit of its own, and the grants of the caller's token
// narrow its answer as an authorizer's would.
type MemberPolicy struct{}

// Authorize answers one request.
func (p MemberPolicy) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	return authz.RestrictByClaims(authorizer.Core, p.decide(req), req), nil
}

// Decide is Authorize under the name latere.ai/x/pkg/authz/server calls
// a decider by, so the policy can also be served as an endpoint.
func (p MemberPolicy) Decide(ctx context.Context, req authz.Request) (authz.Decision, error) {
	return p.Authorize(ctx, req)
}

func (MemberPolicy) decide(req authz.Request) authz.Decision {
	kind := authorizer.Kind(req.Action)
	switch {
	case strings.EqualFold(req.Resource.ID, authz.ProbeID):
		return authz.Decision{Reason: authz.ReasonProbe}
	case req.Subject == "" || req.Sub == "":
		return authz.Decision{Reason: authz.ReasonAnonymous}
	case kind == "" || kind != req.Resource.Kind:
		return authz.Decision{Reason: ReasonUnknownAction}
	}
	allow := authz.Decision{Allow: true}
	person := req.Resource.String(authorizer.FieldPerson)
	switch req.Action {
	case authorizer.ActionConversationAssistantRead, authorizer.ActionConversationAssistantPost:
		return authz.Decision{Reason: ReasonNoAssistant}
	case authorizer.ActionConversationCreate:
		if slices.Equal(stringList(req.Resource.Fields[authorizer.FieldPeople]), []string{req.Sub}) {
			return allow
		}
		return authz.Decision{Reason: ReasonNotYours}
	case authorizer.ActionConversationList:
		if person == req.Sub {
			return allow
		}
		return authz.Decision{Reason: ReasonNotYours}
	case authorizer.ActionDeviceList, authorizer.ActionKeyPackageClaim:
		return allow
	}
	if kind == authorizer.KindConversation {
		if slices.Contains(stringList(req.Resource.Fields[authorizer.FieldPeople]), req.Sub) {
			return allow
		}
		return authz.Decision{Reason: ReasonNotMember}
	}
	if person == req.Sub {
		return allow
	}
	return authz.Decision{Reason: ReasonNotYours}
}

// stringList reads a field that holds a list of strings, as sermod sends it
// in process or as it decodes from JSON.
func stringList(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}
