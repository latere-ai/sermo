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
	"errors"
	"fmt"
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
	// trial: nothing survives a restart.
	DatabaseURL string // SERMO_DATABASE_URL

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
	ServiceKey     ed25519.PrivateKey

	// InstallationKey is the Ed25519 public key that attests the
	// assistant's member, in standard base64. Empty admits no assistant.
	InstallationKey ed25519.PublicKey // SERMO_INSTALLATION_KEY

	MaxRequestBytes int64         // SERMO_MAX_REQUEST_BYTES
	Retention       time.Duration // SERMO_RETENTION
}

// Durable reports whether the server keeps its state in a database.
func (s Settings) Durable() bool { return s.DatabaseURL != "" }

// Secret is a value read from a file that no log line prints.
type Secret struct{ value string }

// NewSecret wraps a value.
func NewSecret(v string) Secret { return Secret{value: v} }

// Reveal is the value.
func (s Secret) Reveal() string { return s.value }

const redacted = "[redacted]"

// String keeps %v from printing the value.
func (s Secret) String() string { return redacted }

// GoString keeps %#v from printing the value.
func (s Secret) GoString() string { return redacted }

// LogValue keeps a structured log line from printing the value.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// FromEnv reads the settings. getenv is os.Getenv, or a test's own.
// Every problem is reported, each naming its variable and never its
// value.
func FromEnv(getenv func(string) string) (Settings, error) {
	s := Settings{
		Addr: DefaultAddr, OIDCAudiences: []string{DefaultAudience},
		MaxRequestBytes: DefaultMaxRequestBytes, Retention: DefaultRetention,
	}
	r := reader{getenv: getenv}
	if v := r.text("SERMO_ADDR"); v != "" {
		s.Addr = v
	}
	s.DatabaseURL = r.text("SERMO_DATABASE_URL")
	s.OIDCIssuers = r.urls("SERMO_OIDC_ISSUERS")
	if v := r.list("SERMO_OIDC_AUDIENCE"); len(v) > 0 {
		s.OIDCAudiences = v
	}
	if v := r.text("SERMO_AUTHORIZER_URL"); v != "" {
		if u, ok := httpURL(v); ok {
			s.AuthorizerURL = u
		} else {
			r.fail("SERMO_AUTHORIZER_URL", "is not an http or https address")
		}
	}
	s.AuthorizerTokenFile = r.text("SERMO_AUTHORIZER_TOKEN_FILE")
	s.ServiceKeyFile = r.text("SERMO_SERVICE_KEY_FILE")
	if v := r.text("SERMO_INSTALLATION_KEY"); v != "" {
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
	if len(r.errs) > 0 {
		return Settings{}, errors.Join(r.errs...)
	}
	var err error
	if s.AuthorizerURL != "" {
		if s.AuthorizerToken, err = readSecret("SERMO_AUTHORIZER_TOKEN_FILE", s.AuthorizerTokenFile); err != nil {
			return Settings{}, err
		}
	}
	if s.ServiceKeyFile != "" {
		seed, err := readSecret("SERMO_SERVICE_KEY_FILE", s.ServiceKeyFile)
		if err != nil {
			return Settings{}, err
		}
		b, err := base64.StdEncoding.DecodeString(seed.Reveal())
		if err != nil || len(b) != ed25519.SeedSize {
			return Settings{}, errors.New("SERMO_SERVICE_KEY_FILE does not hold a 32-byte Ed25519 seed in standard base64")
		}
		s.ServiceKey = ed25519.NewKeyFromSeed(b)
	}
	return s, nil
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
	if path == "" {
		return Secret{}, fmt.Errorf("%s is not set", name)
	}
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

func (r *reader) text(name string) string { return strings.TrimSpace(r.getenv(name)) }

// list is a comma-separated list, each entry trimmed and empty ones
// dropped.
func (r *reader) list(name string) []string {
	var out []string
	for entry := range strings.SplitSeq(r.text(name), ",") {
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

func (r *reader) flag(name string) bool {
	v := r.text(name)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.fail(name, "is not true or false")
	}
	return b
}

func (r *reader) size(name string, into *int64) {
	v := r.text(name)
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
	v := r.text(name)
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
