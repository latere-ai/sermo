// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package store is what sermod keeps: the directory of devices, the
// recovery records, the key packages, and each conversation with its
// group's public state, its ordered log and the welcomes it filed. It
// holds ciphertext and public state only. Two implementations meet one
// contract, which package storetest drives: memory for a trial and the
// tests, and postgres for a server that keeps its state.
package store

import (
	"context"
	"errors"
	"slices"
	"time"

	"latere.ai/x/sdk-go/messaging"
)

// The errors of the contract.
var (
	// ErrNotFound is an object that is not there.
	ErrNotFound = errors.New("store: not found")
	// ErrExists is a create of an object that is there already.
	ErrExists = errors.New("store: already exists")
	// ErrConflict is an append whose conversation changed since its
	// caller read it.
	ErrConflict = errors.New("store: the conversation changed")
)

// Store is the contract of both implementations. Every method is safe
// for concurrent use.
type Store interface {
	// PutDevice adds a directory record of a person, a device's or a
	// recovery key's, or replaces the one with its id, when check, given
	// the person's directory as it is at the write, says to.
	PutDevice(ctx context.Context, r messaging.DeviceRecord, check DirectoryCheck) error
	// Devices lists every record of a person by id.
	Devices(ctx context.Context, person string) ([]messaging.DeviceRecord, error)
	// AddRevocation keeps a revocation of a person's, once however often
	// it is added, and when device is not empty deletes that device's key
	// packages and transfer, in one transaction, when check, given the
	// person's directory as it is at the write, says to.
	AddRevocation(ctx context.Context, v messaging.Revocation, device string, check DirectoryCheck) error
	// Revocations lists every revocation of a person, in the order they
	// were added.
	Revocations(ctx context.Context, person string) ([]messaging.Revocation, error)

	// PutRecovery stores a person's wrapped backup key, replacing the
	// earlier one.
	PutRecovery(ctx context.Context, person string, wrapped []byte) error
	// Recovery is a person's wrapped backup key. ErrNotFound when the
	// person has none.
	Recovery(ctx context.Context, person string) ([]byte, error)
	// PutTransfer leaves a backup key sealed to a device, replacing an
	// earlier one.
	PutTransfer(ctx context.Context, person, device string, sealed []byte) error
	// TakeTransfer returns what was left for a device and deletes it.
	TakeTransfer(ctx context.Context, person, device string) ([]byte, error)

	// AddKeyPackages adds a device's key packages. A last resort replaces
	// the device's earlier one.
	AddKeyPackages(ctx context.Context, kps []KeyPackage) error
	// CountKeyPackages is how many one-time key packages a device has
	// left, and whether it has a last resort.
	CountKeyPackages(ctx context.Context, person, device string) (n int, lastResort bool, err error)
	// ClaimKeyPackage hands out a device's oldest one-time key package,
	// deleting it, or its last resort, keeping it. ErrNotFound when it
	// has neither.
	ClaimKeyPackage(ctx context.Context, person, device string) (KeyPackage, error)

	// CreateConversation stores a new conversation with its first state,
	// at seq 0 and version 0 whatever it is handed: like its times, they
	// are the store's. ErrExists when the id is taken.
	CreateConversation(ctx context.Context, c Conversation) error
	// Conversation reads one conversation.
	Conversation(ctx context.Context, id string) (Conversation, error)
	// Conversations lists the conversations a person is one of the
	// people of, by id, after the id after: at most limit of them, and
	// none when limit is below one.
	Conversations(ctx context.Context, person, after string, limit int) ([]Conversation, error)
	// Append appends a message to a conversation read at version, in one
	// transaction: the message takes the next sequence number, and the
	// append's state, when it carries one, replaces the conversation's,
	// and its welcomes are filed. ErrConflict when the conversation's
	// version is no longer the one read.
	Append(ctx context.Context, id string, version int64, a Append) (Message, error)
	// Messages lists a conversation's messages after a sequence number,
	// oldest first: at most limit of them, and none when limit is below
	// one.
	Messages(ctx context.Context, id string, after int64, limit int) ([]Message, error)
	// Welcomes lists the welcomes filed for a device, oldest first.
	Welcomes(ctx context.Context, person, device string) ([]Welcome, error)
	// DeleteWelcome deletes one of a device's welcomes.
	DeleteWelcome(ctx context.Context, person, device, id string) error
	// DeleteMessagesBefore deletes every message stored before the time,
	// and every welcome filed before it, and says how many messages went.
	DeleteMessagesBefore(ctx context.Context, before time.Time) (int, error)
}

// DirectoryCheck decides a directory write from a person's records and
// revocations as they are at the write; write false makes the call a
// no-op. No other directory write of the person, a PutDevice or an
// AddRevocation, falls between the directory check sees and the write it
// decides, so two writes cannot both pass on one directory. An error from
// check is the call's, unchanged.
//
// check runs while the person's directory is held, so it decides from
// what it is given and calls nothing of the store's. The records and
// revocations are its own to change. A nil check writes.
type DirectoryCheck func(records []messaging.DeviceRecord, revocations []messaging.Revocation) (write bool, err error)

// KeyPackage is one key package of a device.
type KeyPackage struct {
	// Ref is the key package's reference, hex.
	Ref    string
	Person string
	Device string
	// Data is the key package as the device encoded it.
	Data       []byte
	LastResort bool
	Created    time.Time
}

// Conversation is one conversation and its group's public state at its
// current epoch.
type Conversation struct {
	ID    string
	Kind  messaging.Kind
	Level messaging.Level
	// People and Owners are the state's, as the epoch holds it.
	People []string
	Owners []string
	Epoch  uint64
	// Seq is the sequence number of the last message, 0 before the first.
	Seq int64
	// Version counts the changes to View: every proposal and commit.
	Version int64
	// View is the group's mls.PublicGroup, as MarshalBinary encodes it.
	View []byte
	// GroupInfo is the latest group info, with the ratchet tree and the
	// external public key.
	GroupInfo []byte
	// Members are the devices that have been leaves of the group, each
	// with the epochs of the log it may read.
	Members []Member
	Created time.Time
	Updated time.Time
}

// Member is a device's span in a conversation's log, in epochs: from
// the epoch the commit that added it starts, until the epoch the commit
// that removed it starts, 0 while it is a leaf. A removed device reads
// the commit that removed it, which belongs to the epoch before.
type Member struct {
	Person string
	Device string
	Since  uint64
	Until  uint64
}

// Has reports whether the person is one of the conversation's people.
func (c *Conversation) Has(person string) bool {
	return slices.Contains(c.People, person)
}

// MayRead reports whether a device may read a message of an epoch:
// whether one of its spans holds it.
func (c *Conversation) MayRead(person, device string, epoch uint64) bool {
	for _, m := range c.Members {
		if m.Person == person && m.Device == device && epoch >= m.Since && (m.Until == 0 || epoch < m.Until) {
			return true
		}
	}
	return false
}

// Leaf reports whether the device is a leaf of the group now.
func (c *Conversation) Leaf(person, device string) bool {
	for _, m := range c.Members {
		if m.Person == person && m.Device == device && m.Until == 0 {
			return true
		}
	}
	return false
}

// MessageKind is what a message of the log is.
type MessageKind string

// The kinds of message.
const (
	KindApplication MessageKind = "application"
	KindProposal    MessageKind = "proposal"
	KindCommit      MessageKind = "commit"
)

// Message is one message of a conversation's log.
type Message struct {
	Conversation string
	Seq          int64
	Epoch        uint64
	Kind         MessageKind
	// Data is the MLS message.
	Data []byte
	// Person and Device sent it; both are empty for a proposal of the
	// service's own.
	Person  string
	Device  string
	Created time.Time
}

// Welcome is a Welcome filed for a device a commit added.
type Welcome struct {
	ID           string
	Person       string
	Device       string
	Conversation string
	// Seq is the commit's sequence number.
	Seq int64
	// Data is the Welcome message.
	Data []byte
	// Notice is the commit's authenticated data, its history notice.
	Notice  []byte
	Created time.Time
}

// Append is what one message appends.
type Append struct {
	Message Message
	// State replaces the conversation's state when set: a proposal's new
	// view, or a commit's new epoch. Its ID, Seq, Version and Created are
	// the store's.
	State *Conversation
	// Welcomes are filed for the devices a commit added; the store sets
	// their Seq.
	Welcomes []Welcome
}
