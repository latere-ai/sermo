// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package conv

import (
	"testing"

	"latere.ai/x/sdk-go/mls"

	"latere.ai/x/sermo/authorizer"
)

// Each kind of proposal a person sends is asked about as the change it
// makes, and an update as a change of devices.
func TestProposalChange(t *testing.T) {
	for k, want := range map[mls.ProposalKind]string{
		mls.ProposalAdd:                    authorizer.ChangeAddPeople,
		mls.ProposalRemove:                 authorizer.ChangeRemovePeople,
		mls.ProposalGroupContextExtensions: authorizer.ChangeOwners,
		mls.ProposalUpdate:                 authorizer.ChangeDevices,
	} {
		if got := proposalChange(k); got != want {
			t.Errorf("proposalChange(%v) = %q, want %q", k, got, want)
		}
	}
}

// A limit of zero or less is the default, and one past the maximum is
// the maximum.
func TestClampLimit(t *testing.T) {
	for limit, want := range map[int]int{-1: DefaultListLimit, 0: DefaultListLimit, 1: 1, MaxListLimit: MaxListLimit, MaxListLimit + 1: MaxListLimit} {
		if got := clampLimit(limit); got != want {
			t.Errorf("clampLimit(%d) = %d, want %d", limit, got, want)
		}
	}
}
