// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authorizer

import (
	"slices"

	"latere.ai/x/pkg/authz"
)

// Core is the name the shared contract carries this vocabulary under.
const Core = "sermo"

// The resource kinds. An action acts on exactly one.
const (
	KindConversation = "Conversation"
	KindDevice       = "Device"
	KindKeyPackage   = "KeyPackage"
	KindBackup       = "Backup"
)

// The actions: every question sermod asks, in the order of the table of
// specs/003-identity-and-authorization.md.
const (
	// ActionConversationCreate is asked by creating a conversation, with
	// the state its group starts with: its creator alone, the owner, and
	// the level off.
	ActionConversationCreate = "conversation.create"
	// ActionConversationRead is asked by every read of a conversation: its
	// record, its group info, its messages and its welcomes.
	ActionConversationRead = "conversation.read"
	// ActionConversationList is asked by the list of a person's
	// conversations.
	ActionConversationList = "conversation.list"
	// ActionConversationSend is asked by sending an application message,
	// with its size.
	ActionConversationSend = "conversation.send"
	// ActionConversationCommit is asked by a commit the conversation's
	// rules accept, and by a proposal that is not a leave, with what it
	// changes; and by an owner's request for the assistant's key
	// package.
	ActionConversationCommit = "conversation.commit"
	// ActionConversationLeave is asked by a proposal that removes its
	// sender's own leaves.
	ActionConversationLeave = "conversation.leave"
	// ActionConversationMembership is asked by a caller that asks whether
	// a person is one of the conversation's people, as the plane does to
	// decide a read of a file sent in the conversation.
	ActionConversationMembership = "conversation.membership"
	// ActionConversationAssistantRead is asked by a caller that reads the
	// conversation as the assistant's member reads it.
	ActionConversationAssistantRead = "conversation.assistant_read"
	// ActionConversationAssistantPost is asked by a caller that posts an
	// answer to the group as the assistant's member.
	ActionConversationAssistantPost = "conversation.assistant_post"

	// ActionDeviceRegister is asked by registering a device record.
	ActionDeviceRegister = "device.register"
	// ActionDeviceVouch is asked by leaving the backup key for a new
	// device, and by the new device fetching it.
	ActionDeviceVouch = "device.vouch"
	// ActionDeviceList is asked by listing a person's records.
	ActionDeviceList = "device.list"
	// ActionDeviceDelete is asked by revoking a device.
	ActionDeviceDelete = "device.delete"

	// ActionKeyPackagePublish is asked by publishing key packages, and by
	// reading how many are left.
	ActionKeyPackagePublish = "key_package.publish"
	// ActionKeyPackageClaim is asked by claiming a person's key packages
	// for a conversation.
	ActionKeyPackageClaim = "key_package.claim"

	// ActionBackupRecovery is asked by registering and reading the
	// recovery record and the wrapped backup key.
	ActionBackupRecovery = "backup.recovery"
)

// The fields a resource carries beside its kind and id.
const (
	// FieldConversationKind is one_on_one or group.
	FieldConversationKind = "conversation_kind"
	// FieldPeople and FieldOwners are the conversation's people and
	// owners, as subjects, in the order they joined.
	FieldPeople = "people"
	FieldOwners = "owners"
	// FieldLevel is off, reads_along or takes_part.
	FieldLevel = "level"
	// FieldSize is a sent message's length in bytes.
	FieldSize = "size"
	// FieldChanges lists what a commit changes, of the Change values.
	FieldChanges = "changes"
	// FieldAddPeople and FieldRemovePeople are the people a commit adds
	// and removes.
	FieldAddPeople    = "add_people"
	FieldRemovePeople = "remove_people"
	// FieldNewOwners and FieldNewLevel are the owners and the level a
	// commit leaves.
	FieldNewOwners = "new_owners"
	FieldNewLevel  = "new_level"
	// FieldAskedBy is the person an answer posted as the assistant
	// answers.
	FieldAskedBy = "asked_by"
	// FieldPerson is whose record, key package or backup it is; on a
	// claim, the person claimed for.
	FieldPerson = "person"
	// FieldRoot says a device registers as a new root, vouched for by
	// none of the person's records.
	FieldRoot = "root"
	// FieldDevice is the device a key package is published for.
	FieldDevice = "device"
	// FieldConversation is the conversation a claim is for.
	FieldConversation = "conversation"
)

// The values of FieldChanges.
const (
	ChangeAddPeople    = "add_people"
	ChangeRemovePeople = "remove_people"
	ChangeOwners       = "owners"
	ChangeLevel        = "level"
	ChangeDevices      = "devices"
)

// action is one row of the vocabulary table.
type action struct {
	name, kind string
	fields     []string
	id         bool
}

// conversation is the facts of a conversation every question about one
// carries.
var conversation = []string{FieldConversationKind, FieldPeople, FieldOwners, FieldLevel}

func with(extra ...string) []string { return append(slices.Clone(conversation), extra...) }

// table is the vocabulary of specs/003-identity-and-authorization.md, in
// its order.
var table = []action{
	{ActionConversationCreate, KindConversation, with(), true},
	{ActionConversationRead, KindConversation, with(), true},
	{ActionConversationList, KindConversation, []string{FieldPerson}, false},
	{ActionConversationSend, KindConversation, with(FieldSize), true},
	{ActionConversationCommit, KindConversation, with(FieldChanges, FieldAddPeople, FieldRemovePeople, FieldNewOwners, FieldNewLevel), true},
	{ActionConversationLeave, KindConversation, with(), true},
	{ActionConversationMembership, KindConversation, with(FieldPerson), true},
	{ActionConversationAssistantRead, KindConversation, with(), true},
	{ActionConversationAssistantPost, KindConversation, with(FieldAskedBy), true},
	{ActionDeviceRegister, KindDevice, []string{FieldPerson, FieldRoot}, false},
	{ActionDeviceVouch, KindDevice, []string{FieldPerson}, true},
	{ActionDeviceList, KindDevice, []string{FieldPerson}, false},
	{ActionDeviceDelete, KindDevice, []string{FieldPerson}, true},
	{ActionKeyPackagePublish, KindKeyPackage, []string{FieldPerson, FieldDevice}, false},
	{ActionKeyPackageClaim, KindKeyPackage, []string{FieldPerson, FieldConversation}, false},
	{ActionBackupRecovery, KindBackup, []string{FieldPerson}, false},
}

// vocabulary is the table as the shared contract reads it, built once. A
// table that does not build is a mistake in this file, which the
// package's tests find.
var vocabulary = func() authz.Vocabulary {
	actions := make([]authz.Action, len(table))
	for i, a := range table {
		actions[i] = authz.Action{Name: a.name, Kind: a.kind}
	}
	v, err := authz.NewVocabulary(Core, actions...)
	if err != nil {
		panic(err)
	}
	return v.WithLabels(map[string]string{
		KindConversation: "Conversations", KindDevice: "Devices", KindKeyPackage: "Key packages", KindBackup: "Backups",
	})
}()

// Vocabulary is the whole action table, for an authorizer to validate
// against and for the conformance suite to drive a case per row from.
func Vocabulary() authz.Vocabulary { return vocabulary }

// Actions lists every action in the order of the table.
func Actions() []string {
	out := make([]string, len(table))
	for i, a := range table {
		out[i] = a.name
	}
	return out
}

// Kind is the resource kind an action acts on, and "" for a string that
// is no action of the table.
func Kind(name string) string {
	kind, _ := vocabulary.Kind(name)
	return kind
}

// Known reports whether name is an action of the table.
func Known(name string) bool { return vocabulary.Known(name) }

// Fields lists the fields an action's resource may carry beside its kind
// and id. The value is a fresh copy.
func Fields(name string) []string {
	for _, a := range table {
		if a.name == name {
			return slices.Clone(a.fields)
		}
	}
	return nil
}

// SendsID reports whether an action's resource carries an id: the
// conversation's, or the device's.
func SendsID(name string) bool {
	for _, a := range table {
		if a.name == name {
			return a.id
		}
	}
	return false
}
