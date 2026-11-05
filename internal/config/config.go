// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package config reads what an operator sets: every SERMO_* variable,
// once, at start, into one typed value. No other package of the module
// reads the environment.
//
// A value that does not parse is an error that names its variable and
// never its value, since a variable may name a secret.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// The defaults.
const (
	DefaultAddr     = ":8080"
	DefaultAudience = "sermo"
	// DefaultMaxRequestBytes bounds a request body: a commit with its
	// group info and ratchet tree for the largest group is the largest.
	DefaultMaxRequestBytes = 8 << 20
	// DefaultRetention is how long a message's ciphertext is kept for
	// devices that have not fetched it.
	DefaultRetention = 30 * 24 * time.Hour
)

// Settings are the settings of the process.
type Settings struct {
	Addr string // SERMO_ADDR
	// DatabaseURL is Postgres. Empty keeps everything in memory, for a
	// trial: nothing survives a restart. It may carry a password, so it
	// prints as a placeholder.
	DatabaseURL Secret // SERMO_DATABASE_URL
	// DatabasePoolURL is a pooled endpoint of the same database, which
	// the server serves over once its migrations have run over
	// DatabaseURL: a migration holds a session, which a transaction-mode
	// pooler does not keep. Empty serves over DatabaseURL.
	DatabasePoolURL Secret // SERMO_DATABASE_POOL_URL

	// OIDCIssuers are the issuers whose tokens are accepted, and
	// OIDCAudiences the audiences a token may be addressed to.
	OIDCIssuers   []string // SERMO_OIDC_ISSUERS
	OIDCAudiences []string // SERMO_OIDC_AUDIENCE

	// AuthorizerURL is the endpoint asked for every decision; empty
	// decides in process by the member policy.
	AuthorizerURL       string // SERMO_AUTHORIZER_URL
	AuthorizerTokenFile string // SERMO_AUTHORIZER_TOKEN_FILE
	AuthorizerToken     Secret

	// ServiceKey is the Ed25519 key Sermo signs its proposals with as the
	// groups' external sender, read from SERMO_SERVICE_KEY_FILE: the
	// 32-byte seed in standard base64. Without a database a fresh key is
	// made at start.
	ServiceKeyFile string // SERMO_SERVICE_KEY_FILE
	ServiceKey     Key

	// InstallationKey is the Ed25519 public key that attests the
	// assistant's member, in standard base64. Empty admits no assistant.
	InstallationKey ed25519.PublicKey // SERMO_INSTALLATION_KEY

	MaxRequestBytes int64         // SERMO_MAX_REQUEST_BYTES
	Retention       time.Duration // SERMO_RETENTION
}

// MarshalJSON encodes the settings with Retention as integer
// nanoseconds, the form a time.Duration has no default for.
func (s Settings) MarshalJSON() ([]byte, error) {
	type alias Settings
	return json.Marshal(struct {
		alias
		Retention int64
	}{alias(s), int64(s.Retention)})
}

// Durable reports whether the server keeps its state in a database.
func (s Settings) Durable() bool { return s.DatabaseURL.Reveal() != "" }

// Secret is a value no log line prints: one read from a file, or a
// database URL, which may carry a password.
type Secret struct{ value string }

// NewSecret wraps a value.
func NewSecret(v string) Secret { return Secret{value: v} }

// Reveal is the value.
func (s Secret) Reveal() string { return s.value }

const redacted = "[redacted]"

// String keeps the value out of anything that prints the secret.
func (s Secret) String() string { return redacted }

// GoString keeps %#v from printing the value.
func (s Secret) GoString() string { return redacted }

// Format keeps every verb, %d and %x among them, from printing the value.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue keeps a structured log line from printing the value.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON keeps an encoded value of the settings from carrying it.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// Key is a private key read from a file, which prints as a placeholder
// the way a Secret does.
type Key struct{ key ed25519.PrivateKey }

// NewKey wraps a private key.
func NewKey(k ed25519.PrivateKey) Key { return Key{key: k} }

// Private is the key; nil when none was read.
func (k Key) Private() ed25519.PrivateKey { return k.key }

// String keeps the key out of anything that prints it.
func (k Key) String() string { return redacted }

// GoString keeps %#v from printing the key.
func (k Key) GoString() string { return redacted }

// Format keeps every verb from printing the key.
func (k Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue keeps a structured log line from printing the key.
func (k Key) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON keeps an encoded value of the settings from carrying it.
func (k Key) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// FromEnv reads the settings. getenv is os.Getenv, or a test's own.
// Every problem is reported, each naming its variable and never its
// value.
func FromEnv(getenv func(string) string) (Settings, error) {
	s := Settings{
		Addr: DefaultAddr, OIDCAudiences: []string{DefaultAudience},
		MaxRequestBytes: DefaultMaxRequestBytes, Retention: DefaultRetention,
	}
	r := reader{getenv: getenv}
	if v := r.env("SERMO_ADDR"); v != "" {
		s.Addr = v
	}
	s.DatabaseURL = NewSecret(r.env("SERMO_DATABASE_URL"))
	s.DatabasePoolURL = NewSecret(r.env("SERMO_DATABASE_POOL_URL"))
	s.OIDCIssuers = r.urls("SERMO_OIDC_ISSUERS")
	if v := r.list("SERMO_OIDC_AUDIENCE"); len(v) > 0 {
		s.OIDCAudiences = v
	}
	if v := r.env("SERMO_AUTHORIZER_URL"); v != "" {
		if u, ok := httpURL(v); ok {
			s.AuthorizerURL = u
		} else {
			r.fail("SERMO_AUTHORIZER_URL", "is not an http or https address")
		}
	}
	s.AuthorizerTokenFile = r.env("SERMO_AUTHORIZER_TOKEN_FILE")
	s.ServiceKeyFile = r.env("SERMO_SERVICE_KEY_FILE")
	if v := r.env("SERMO_INSTALLATION_KEY"); v != "" {
		k, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(k) != ed25519.PublicKeySize {
			r.fail("SERMO_INSTALLATION_KEY", "is not an Ed25519 public key in standard base64")
		} else {
			s.InstallationKey = k
		}
	}
	r.size("SERMO_MAX_REQUEST_BYTES", &s.MaxRequestBytes)
	r.duration("SERMO_RETENTION", &s.Retention)

	r.errs = append(r.errs, s.refusals()...)
	// The files are read with the rest, so a bad file is reported with
	// every other problem.
	if s.AuthorizerURL != "" && s.AuthorizerTokenFile != "" {
		token, err := readSecret("SERMO_AUTHORIZER_TOKEN_FILE", s.AuthorizerTokenFile)
		if err != nil {
			r.errs = append(r.errs, err)
		}
		s.AuthorizerToken = token
	}
	if s.ServiceKeyFile != "" {
		key, err := readKey("SERMO_SERVICE_KEY_FILE", s.ServiceKeyFile)
		if err != nil {
			r.errs = append(r.errs, err)
		}
		s.ServiceKey = key
	}
	if len(r.errs) > 0 {
		return Settings{}, errors.Join(r.errs...)
	}
	return s, nil
}

// readKey reads an Ed25519 key from the seed its file holds in standard
// base64. The error names the variable, never the content.
func readKey(name, path string) (Key, error) {
	seed, err := readSecret(name, path)
	if err != nil {
		return Key{}, err
	}
	b, err := base64.StdEncoding.DecodeString(seed.Reveal())
	if err != nil || len(b) != ed25519.SeedSize {
		return Key{}, fmt.Errorf("%s does not hold a 32-byte Ed25519 seed in standard base64", name)
	}
	return NewKey(ed25519.NewKeyFromSeed(b)), nil
}

// refusals are the settings a server cannot start with.
func (s Settings) refusals() []error {
	var errs []error
	if len(s.OIDCIssuers) == 0 {
		errs = append(errs, errors.New("SERMO_OIDC_ISSUERS is not set: name the issuers whose tokens this server accepts"))
	}
	if s.AuthorizerURL == "" && s.AuthorizerTokenFile != "" {
		errs = append(errs, errors.New("SERMO_AUTHORIZER_TOKEN_FILE is set and SERMO_AUTHORIZER_URL is not: name the endpoint the bearer is for"))
	}
	if s.AuthorizerURL != "" && s.AuthorizerTokenFile == "" {
		errs = append(errs, errors.New("SERMO_AUTHORIZER_TOKEN_FILE is not set: name the file of the bearer SERMO_AUTHORIZER_URL is asked with"))
	}
	if s.DatabasePoolURL.Reveal() != "" && !s.Durable() {
		errs = append(errs, errors.New("SERMO_DATABASE_POOL_URL is set and SERMO_DATABASE_URL is not: name the direct endpoint the migrations run over"))
	}
	if s.Durable() && s.ServiceKeyFile == "" {
		errs = append(errs, errors.New("SERMO_SERVICE_KEY_FILE is not set: a server with a database keeps one external sender key for every group it serves"))
	}
	if s.MaxRequestBytes < 1<<20 {
		errs = append(errs, errors.New("SERMO_MAX_REQUEST_BYTES is under 1 MiB, too small for a commit with its ratchet tree"))
	}
	return errs
}

// readSecret reads a secret from its file, once. The error names the
// variable, never the content.
func readSecret(name, path string) (Secret, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Secret{}, fmt.Errorf("%s names a file that cannot be read", name)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return Secret{}, fmt.Errorf("%s names an empty file", name)
	}
	return NewSecret(v), nil
}

// reader reads variables and collects what does not parse.
type reader struct {
	getenv func(string) string
	errs   []error
}

func (r *reader) fail(name, why string) { r.errs = append(r.errs, fmt.Errorf("%s %s", name, why)) }

// env is a variable, trimmed. The database names are read through it
// by name at the call, which is the read the postgres gate of
// .lateregate.yaml looks for.
func (r *reader) env(name string) string { return strings.TrimSpace(r.getenv(name)) }

// list is a comma-separated list, each entry trimmed and empty ones
// dropped.
func (r *reader) list(name string) []string {
	var out []string
	for entry := range strings.SplitSeq(r.env(name), ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

// urls is a list of http or https addresses with no trailing slash.
func (r *reader) urls(name string) []string {
	var out []string
	for _, v := range r.list(name) {
		u, ok := httpURL(v)
		if !ok {
			r.fail(name, "holds an entry that is not an http or https address")
			continue
		}
		out = append(out, u)
	}
	return out
}

func (r *reader) size(name string, into *int64) {
	v := r.env(name)
	if v == "" {
		return
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		r.fail(name, "is not a positive number of bytes")
		return
	}
	*into = n
}

func (r *reader) duration(name string, into *time.Duration) {
	v := r.env(name)
	if v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		r.fail(name, "is not a positive duration such as 720h")
		return
	}
	*into = d
}

// httpURL is v with no trailing slash when it is an absolute http or
// https address.
func httpURL(v string) (string, bool) {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return strings.TrimRight(v, "/"), true
}
