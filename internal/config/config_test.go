// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"latere.ai/x/sermo/internal/config"
)

// issuer is the one variable a server cannot start without, so every
// case that is not about it sets it.
const issuer = "https://issuer.example"

// env is a getenv over a map. A case starts from a valid issuer list and
// its overrides; an override to "" unsets a variable.
func env(overrides map[string]string) func(string) string {
	vars := map[string]string{"SERMO_OIDC_ISSUERS": issuer}
	maps.Copy(vars, overrides)
	return func(name string) string { return vars[name] }
}

// file writes content to a fresh file of the test and returns its path.
func file(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// missing is a path in the test's directory that names no file.
func missing(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent")
}

// seed is a fresh Ed25519 seed and its standard base64.
func seed(t *testing.T) ([]byte, string) {
	t.Helper()
	b := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b, base64.StdEncoding.EncodeToString(b)
}

// TestDefaults checks what a server runs with when only the issuers are
// set: the documented defaults, in memory, deciding in process.
func TestDefaults(t *testing.T) {
	s, err := config.FromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := config.Settings{
		Addr: config.DefaultAddr, OIDCIssuers: []string{issuer}, OIDCAudiences: []string{config.DefaultAudience},
		MaxRequestBytes: config.DefaultMaxRequestBytes, Retention: config.DefaultRetention,
	}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("FromEnv = %+v, want %+v", s, want)
	}
	if s.Durable() {
		t.Error("a server without a database reports itself durable")
	}
}

// TestEveryVariable sets every variable and checks each lands in its
// field: trimmed, lists split with empty entries dropped, addresses
// without their trailing slash, and the two files read.
func TestEveryVariable(t *testing.T) {
	seedBytes, seedText := seed(t)
	installation, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := rand.Text()
	tokenFile := file(t, "\n  "+token+"  \n")
	keyFile := file(t, seedText+"\n")
	s, err := config.FromEnv(env(map[string]string{
		"SERMO_ADDR":                  " 127.0.0.1:9000 ",
		"SERMO_DATABASE_URL":          "postgres://sermo@db.example/sermo",
		"SERMO_DATABASE_POOL_URL":     " postgres://sermo@pool.example/sermo?default_query_exec_mode=exec ",
		"SERMO_OIDC_ISSUERS":          " https://one.example/ , ,http://two.example:8443/realm/ ",
		"SERMO_OIDC_AUDIENCE":         "sermo, plane ,,",
		"SERMO_AUTHORIZER_URL":        "https://authz.example/decide/",
		"SERMO_AUTHORIZER_TOKEN_FILE": tokenFile,
		"SERMO_SERVICE_KEY_FILE":      keyFile,
		"SERMO_INSTALLATION_KEY":      base64.StdEncoding.EncodeToString(installation),
		"SERMO_MAX_REQUEST_BYTES":     "2097152",
		"SERMO_RETENTION":             "720h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr != "127.0.0.1:9000" {
		t.Errorf("Addr = %q", s.Addr)
	}
	if s.DatabaseURL != "postgres://sermo@db.example/sermo" || !s.Durable() {
		t.Errorf("DatabaseURL = %q, Durable = %v", s.DatabaseURL, s.Durable())
	}
	if s.DatabasePoolURL != "postgres://sermo@pool.example/sermo?default_query_exec_mode=exec" {
		t.Errorf("DatabasePoolURL = %q", s.DatabasePoolURL)
	}
	if want := []string{"https://one.example", "http://two.example:8443/realm"}; !slices.Equal(s.OIDCIssuers, want) {
		t.Errorf("OIDCIssuers = %q, want %q", s.OIDCIssuers, want)
	}
	if want := []string{"sermo", "plane"}; !slices.Equal(s.OIDCAudiences, want) {
		t.Errorf("OIDCAudiences = %q, want %q", s.OIDCAudiences, want)
	}
	if s.AuthorizerURL != "https://authz.example/decide" {
		t.Errorf("AuthorizerURL = %q", s.AuthorizerURL)
	}
	if s.AuthorizerTokenFile != tokenFile || s.AuthorizerToken.Reveal() != token {
		t.Errorf("AuthorizerTokenFile = %q, the token read is not the file's trimmed content", s.AuthorizerTokenFile)
	}
	if s.ServiceKeyFile != keyFile || !s.ServiceKey.Private().Equal(ed25519.NewKeyFromSeed(seedBytes)) {
		t.Errorf("ServiceKeyFile = %q, the key read is not the one of the file's seed", s.ServiceKeyFile)
	}
	if !bytes.Equal(s.InstallationKey, installation) {
		t.Errorf("InstallationKey = %x, want %x", s.InstallationKey, installation)
	}
	if s.MaxRequestBytes != 2<<20 {
		t.Errorf("MaxRequestBytes = %d", s.MaxRequestBytes)
	}
	if s.Retention != 720*time.Hour {
		t.Errorf("Retention = %v", s.Retention)
	}
}

// TestProblems checks each setting a server refuses to start with: the
// error carries its sentence, and no settings come back with it.
func TestProblems(t *testing.T) {
	_, seedText := seed(t)
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	cases := []struct {
		name string
		vars map[string]string
		want []string
	}{
		{"no issuers", map[string]string{"SERMO_OIDC_ISSUERS": ""},
			[]string{"SERMO_OIDC_ISSUERS is not set"}},
		{"issuers that are only commas", map[string]string{"SERMO_OIDC_ISSUERS": " , ,"},
			[]string{"SERMO_OIDC_ISSUERS is not set"}},
		{"an issuer of another scheme", map[string]string{"SERMO_OIDC_ISSUERS": issuer + ",ftp://files.example"},
			[]string{"SERMO_OIDC_ISSUERS holds an entry that is not an http or https address"}},
		{"an issuer with no host", map[string]string{"SERMO_OIDC_ISSUERS": "https://"},
			[]string{"SERMO_OIDC_ISSUERS holds an entry that is not an http or https address", "SERMO_OIDC_ISSUERS is not set"}},
		{"an issuer that does not parse", map[string]string{"SERMO_OIDC_ISSUERS": "http://[::1"},
			[]string{"SERMO_OIDC_ISSUERS holds an entry that is not an http or https address"}},
		{"an authorizer with no scheme", map[string]string{"SERMO_AUTHORIZER_URL": "authz.example"},
			[]string{"SERMO_AUTHORIZER_URL is not an http or https address"}},
		{"an authorizer that does not parse", map[string]string{"SERMO_AUTHORIZER_URL": "https://authz.example:port"},
			[]string{"SERMO_AUTHORIZER_URL is not an http or https address"}},
		{"an authorizer with no token file", map[string]string{"SERMO_AUTHORIZER_URL": "https://authz.example"},
			[]string{"SERMO_AUTHORIZER_TOKEN_FILE is not set"}},
		{"a token file with no authorizer", map[string]string{"SERMO_AUTHORIZER_TOKEN_FILE": file(t, "bearer")},
			[]string{"SERMO_AUTHORIZER_TOKEN_FILE is set and SERMO_AUTHORIZER_URL is not"}},
		{"a token file that cannot be read", map[string]string{"SERMO_AUTHORIZER_URL": "https://authz.example", "SERMO_AUTHORIZER_TOKEN_FILE": missing(t)},
			[]string{"SERMO_AUTHORIZER_TOKEN_FILE names a file that cannot be read"}},
		{"an empty token file", map[string]string{"SERMO_AUTHORIZER_URL": "https://authz.example", "SERMO_AUTHORIZER_TOKEN_FILE": file(t, " \n\t")},
			[]string{"SERMO_AUTHORIZER_TOKEN_FILE names an empty file"}},
		{"a database with no service key", map[string]string{"SERMO_DATABASE_URL": "postgres://db.example/sermo"},
			[]string{"SERMO_SERVICE_KEY_FILE is not set"}},
		{"a pooled database with no direct one", map[string]string{"SERMO_DATABASE_POOL_URL": "postgres://pool.example/sermo"},
			[]string{"SERMO_DATABASE_POOL_URL is set and SERMO_DATABASE_URL is not"}},
		{"a service key file that cannot be read", map[string]string{"SERMO_SERVICE_KEY_FILE": missing(t)},
			[]string{"SERMO_SERVICE_KEY_FILE names a file that cannot be read"}},
		{"an empty service key file", map[string]string{"SERMO_SERVICE_KEY_FILE": file(t, "\n")},
			[]string{"SERMO_SERVICE_KEY_FILE names an empty file"}},
		{"a service key that is not base64", map[string]string{"SERMO_SERVICE_KEY_FILE": file(t, "not base64!")},
			[]string{"SERMO_SERVICE_KEY_FILE does not hold a 32-byte Ed25519 seed in standard base64"}},
		{"a service key of the wrong length", map[string]string{"SERMO_SERVICE_KEY_FILE": file(t, short)},
			[]string{"SERMO_SERVICE_KEY_FILE does not hold a 32-byte Ed25519 seed in standard base64"}},
		{"an installation key that is not base64", map[string]string{"SERMO_INSTALLATION_KEY": "not base64!"},
			[]string{"SERMO_INSTALLATION_KEY is not an Ed25519 public key in standard base64"}},
		{"an installation key of the wrong length", map[string]string{"SERMO_INSTALLATION_KEY": short},
			[]string{"SERMO_INSTALLATION_KEY is not an Ed25519 public key in standard base64"}},
		{"a size that is not a number", map[string]string{"SERMO_MAX_REQUEST_BYTES": "8MiB"},
			[]string{"SERMO_MAX_REQUEST_BYTES is not a positive number of bytes"}},
		{"a size of zero", map[string]string{"SERMO_MAX_REQUEST_BYTES": "0"},
			[]string{"SERMO_MAX_REQUEST_BYTES is not a positive number of bytes"}},
		{"a negative size", map[string]string{"SERMO_MAX_REQUEST_BYTES": "-1"},
			[]string{"SERMO_MAX_REQUEST_BYTES is not a positive number of bytes"}},
		{"a size under 1 MiB", map[string]string{"SERMO_MAX_REQUEST_BYTES": "1048575"},
			[]string{"SERMO_MAX_REQUEST_BYTES is under 1 MiB"}},
		{"a retention that is not a duration", map[string]string{"SERMO_RETENTION": "30 days"},
			[]string{"SERMO_RETENTION is not a positive duration such as 720h"}},
		{"a retention of zero", map[string]string{"SERMO_RETENTION": "0s"},
			[]string{"SERMO_RETENTION is not a positive duration such as 720h"}},
		{"a negative retention", map[string]string{"SERMO_RETENTION": "-1h"},
			[]string{"SERMO_RETENTION is not a positive duration such as 720h"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := config.FromEnv(env(c.vars))
			if err == nil {
				t.Fatalf("FromEnv accepted %v", c.vars)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not say %q", err, w)
				}
			}
			if !reflect.DeepEqual(s, config.Settings{}) {
				t.Errorf("FromEnv returned settings with its error: %+v", s)
			}
		})
	}
	// The seed case that parses stays valid, so the table above fails for
	// its own reason and not for a seed this test made badly.
	if _, err := config.FromEnv(env(map[string]string{"SERMO_SERVICE_KEY_FILE": file(t, seedText)})); err != nil {
		t.Errorf("a valid seed file was refused: %v", err)
	}
}

// TestSeveralProblems checks that the problems of one start are reported
// together, each on its own line, so an operator fixes them in one pass.
func TestSeveralProblems(t *testing.T) {
	_, err := config.FromEnv(env(map[string]string{
		"SERMO_OIDC_ISSUERS":          "",
		"SERMO_AUTHORIZER_URL":        "authz.example",
		"SERMO_AUTHORIZER_TOKEN_FILE": file(t, "bearer"),
		"SERMO_DATABASE_URL":          "postgres://db.example/sermo",
		"SERMO_INSTALLATION_KEY":      "short",
		"SERMO_MAX_REQUEST_BYTES":     "4096",
		"SERMO_RETENTION":             "forever",
	}))
	if err == nil {
		t.Fatal("FromEnv accepted seven problems")
	}
	want := []string{
		"SERMO_AUTHORIZER_URL is not an http or https address",
		"SERMO_INSTALLATION_KEY is not an Ed25519 public key in standard base64",
		"SERMO_RETENTION is not a positive duration such as 720h",
		"SERMO_OIDC_ISSUERS is not set",
		"SERMO_AUTHORIZER_TOKEN_FILE is set and SERMO_AUTHORIZER_URL is not",
		"SERMO_SERVICE_KEY_FILE is not set",
		"SERMO_MAX_REQUEST_BYTES is under 1 MiB",
	}
	lines := strings.Split(err.Error(), "\n")
	if len(lines) != len(want) {
		t.Errorf("got %d problems, want %d:\n%v", len(lines), len(want), err)
	}
	for _, w := range want {
		if !slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, w) }) {
			t.Errorf("no line says %q:\n%v", w, err)
		}
	}
}

// TestErrorsNameTheVariableNotTheValue plants a canary in each value that
// fails and checks the error names the variable and never carries the
// canary, since a variable, or the file it names, may hold a secret.
func TestErrorsNameTheVariableNotTheValue(t *testing.T) {
	canary := "canary-" + rand.Text()
	dir := t.TempDir()
	cases := []struct {
		name string
		vars map[string]string
	}{
		{"SERMO_OIDC_ISSUERS", map[string]string{"SERMO_OIDC_ISSUERS": "ftp://" + canary}},
		{"SERMO_AUTHORIZER_URL", map[string]string{"SERMO_AUTHORIZER_URL": canary}},
		{"SERMO_AUTHORIZER_TOKEN_FILE", map[string]string{"SERMO_AUTHORIZER_URL": "https://authz.example", "SERMO_AUTHORIZER_TOKEN_FILE": filepath.Join(dir, canary)}},
		{"SERMO_SERVICE_KEY_FILE", map[string]string{"SERMO_SERVICE_KEY_FILE": file(t, canary)}},
		{"SERMO_SERVICE_KEY_FILE", map[string]string{"SERMO_SERVICE_KEY_FILE": filepath.Join(dir, canary)}},
		{"SERMO_INSTALLATION_KEY", map[string]string{"SERMO_INSTALLATION_KEY": canary}},
		{"SERMO_MAX_REQUEST_BYTES", map[string]string{"SERMO_MAX_REQUEST_BYTES": canary}},
		{"SERMO_RETENTION", map[string]string{"SERMO_RETENTION": canary}},
	}
	for _, c := range cases {
		_, err := config.FromEnv(env(c.vars))
		if err == nil {
			t.Errorf("%s: FromEnv accepted a canary", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.name) {
			t.Errorf("%s: the error does not name the variable: %v", c.name, err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("%s: the error carries the value: %v", c.name, err)
		}
	}
}

// TestSecretIsRedacted checks that a secret and the service key print as
// a placeholder through every way a log line formats a value, alone and
// as fields of the settings, and that Reveal and Private still give
// them.
func TestSecretIsRedacted(t *testing.T) {
	value := "canary-" + rand.Text()
	s := config.NewSecret(value)
	if s.Reveal() != value {
		t.Fatalf("Reveal = %q, want the value wrapped", s.Reveal())
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	k := config.NewKey(priv)
	if !k.Private().Equal(priv) {
		t.Fatal("Private is not the key wrapped")
	}
	// What a printed key would show: its bytes as numbers, in hex, or in
	// base64.
	numbers := make([]string, len(priv))
	for i, b := range priv {
		numbers[i] = strconv.Itoa(int(b))
	}
	leaks := []string{value, strings.Join(numbers, " "), hex.EncodeToString(priv), strings.ToUpper(hex.EncodeToString(priv)), base64.StdEncoding.EncodeToString(priv)}
	settings := config.Settings{AuthorizerToken: s, ServiceKey: k}
	var printed []string
	for _, verb := range []string{"%v", "%+v", "%s", "%q", "%#v", "%d", "%x", "%X", "%08v"} {
		printed = append(printed, fmt.Sprintf(verb, s), fmt.Sprintf(verb, k), fmt.Sprintf(verb, settings), fmt.Sprintf(verb, &settings))
	}
	printed = append(printed, s.String(), s.GoString(), k.String(), k.GoString(), fmt.Sprint(s, k), fmt.Sprintln(s, k))
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	printed = append(printed, string(encoded))
	for _, p := range printed {
		for _, leak := range leaks {
			if strings.Contains(p, leak) {
				t.Errorf("a secret printed: %s", p)
			}
		}
		if !strings.Contains(p, "[redacted]") {
			t.Errorf("a secret printed without its placeholder: %s", p)
		}
	}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("start", slog.Any("token", s), slog.Any("key", k), slog.Any("settings", settings))
	slog.New(slog.NewJSONHandler(&js, nil)).Info("start", slog.Any("token", s), slog.Any("key", k), slog.Any("settings", settings))
	for _, line := range []string{text.String(), js.String()} {
		for _, leak := range leaks {
			if strings.Contains(line, leak) {
				t.Errorf("a log line printed a secret: %s", line)
			}
		}
		if strings.Count(line, "[redacted]") != 4 {
			t.Errorf("a log line printed a secret without its placeholder: %s", line)
		}
	}
}

// TestBothFilesReported checks that a bad token file and a bad key file
// are reported together.
func TestBothFilesReported(t *testing.T) {
	_, err := config.FromEnv(env(map[string]string{
		"SERMO_AUTHORIZER_URL":        "https://authz.example",
		"SERMO_AUTHORIZER_TOKEN_FILE": missing(t),
		"SERMO_SERVICE_KEY_FILE":      file(t, "not base64!"),
	}))
	if err == nil {
		t.Fatal("FromEnv accepted two bad files")
	}
	for _, w := range []string{"SERMO_AUTHORIZER_TOKEN_FILE names a file that cannot be read",
		"SERMO_SERVICE_KEY_FILE does not hold a 32-byte Ed25519 seed in standard base64"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not say %q", err, w)
		}
	}
}
