// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func itoa(n int) string { return strconv.Itoa(n) }

func TestResolveVaultRefBSMHappyPath(t *testing.T) {
	t.Parallel()
	cfg := vaultTestConfigBSM(t, "0.fdbe5b5b-machine-token-94char-........................................................................")

	got, err := resolveVaultRef(cfg, cfg.Profiles["bsm-fetch"], Request{
		Kind:     requestKindVault,
		Profile:  "bsm-fetch",
		Resource: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		VaultRef: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
	}, mockExecutor(t, func(ctx context.Context, bin string, args []string, env []string) ([]byte, error) {
		if bin != "bws" {
			t.Fatalf("expected bws, got %s", bin)
		}
		if !sliceEqual(args, []string{"secret", "get", "5da84bec-9b21-4e7f-a720-b41b00cad9d5", "--output", "json"}) {
			t.Fatalf("unexpected args: %v", args)
		}
		if !envContains(env, "BWS_ACCESS_TOKEN=0.fdbe5b5b-machine-token-94char-........................................................................") {
			t.Fatal("BWS_ACCESS_TOKEN not propagated to subprocess env")
		}
		return []byte(`{"id":"5da84bec-9b21-4e7f-a720-b41b00cad9d5","key":"basilisk-dev/BASILISK_S3_BUCKET","value":"basilisk"}`), nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "basilisk" {
		t.Fatalf("expected basilisk, got %q", got)
	}
}

func TestResolveVaultRefBWHappyPathPerField(t *testing.T) {
	t.Parallel()
	cfg, sessionFile := vaultTestConfigBW(t, "session-token-89-bytes-...................................................")
	_ = sessionFile

	for _, field := range []string{"password", "username", "notes", "totp"} {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			profile := cfg.Profiles["bw-fetch"]
			profile.VaultFields = []string{field} // narrow to just this field for this run
			got, err := resolveVaultRef(cfg, profile, Request{
				Kind:       requestKindVault,
				Profile:    "bw-fetch",
				Resource:   "2captcha.com",
				VaultRef:   "2captcha.com",
				VaultField: field,
			}, mockExecutor(t, func(ctx context.Context, bin string, args []string, env []string) ([]byte, error) {
				if bin != "bw" {
					t.Fatalf("expected bw, got %s", bin)
				}
				if args[0] != "get" || args[1] != field || args[2] != "2captcha.com" {
					t.Fatalf("unexpected args: %v", args)
				}
				if !sliceContains(args, "--session") || !sliceContains(args, "--raw") {
					t.Fatalf("expected --session and --raw flags, got %v", args)
				}
				// bw should NEVER receive the session via env — only via --session arg
				for _, e := range env {
					if strings.HasPrefix(e, "BW_SESSION=") {
						t.Fatal("BW_SESSION leaked into subprocess env (should be passed via --session)")
					}
				}
				return []byte("the-secret-value-for-" + field + "\n"), nil
			}))
			if err != nil {
				t.Fatalf("unexpected error for field %s: %v", field, err)
			}
			want := "the-secret-value-for-" + field
			if got != want {
				t.Fatalf("field %s: got %q want %q", field, got, want)
			}
		})
	}
}

func TestResolveVaultRefBWLockedFailsClosed(t *testing.T) {
	t.Parallel()
	// Empty session file = locked vault
	cfg, _ := vaultTestConfigBW(t, "")
	_, err := resolveVaultRef(cfg, cfg.Profiles["bw-fetch"], Request{
		Kind:       requestKindVault,
		Profile:    "bw-fetch",
		Resource:   "2captcha.com",
		VaultRef:   "2captcha.com",
		VaultField: "password",
	}, mockExecutor(t, func(ctx context.Context, bin string, args []string, env []string) ([]byte, error) {
		t.Fatal("subprocess should not be invoked when vault is locked")
		return nil, nil
	}))
	if err == nil {
		t.Fatal("expected locked-vault error, got nil")
	}
	if !strings.Contains(err.Error(), "empty") && !strings.Contains(err.Error(), "locked") {
		t.Fatalf("expected locked-vault error wording, got %v", err)
	}
}

func TestResolveVaultRefMissingAuthSource(t *testing.T) {
	t.Parallel()
	cfg := vaultTestConfigBSM(t, "valid-token")
	prof := cfg.Profiles["bsm-fetch"]
	prof.VaultAuth = "does_not_exist"
	_, err := resolveVaultRef(cfg, prof, Request{
		Kind:     requestKindVault,
		Profile:  "bsm-fetch",
		Resource: "x",
		VaultRef: "x",
	}, mockExecutor(t, func(ctx context.Context, bin string, args []string, env []string) ([]byte, error) {
		t.Fatal("executor should not be reached when auth source is missing")
		return nil, nil
	}))
	if err == nil || !strings.Contains(err.Error(), "unknown secret source") {
		t.Fatalf("expected unknown-secret-source error, got %v", err)
	}
}

func TestResolveVaultRefBSMSubprocessError(t *testing.T) {
	t.Parallel()
	cfg := vaultTestConfigBSM(t, "valid-token")
	_, err := resolveVaultRef(cfg, cfg.Profiles["bsm-fetch"], Request{
		Kind:     requestKindVault,
		Profile:  "bsm-fetch",
		Resource: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		VaultRef: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
	}, mockExecutor(t, func(ctx context.Context, bin string, args []string, env []string) ([]byte, error) {
		return nil, errors.New("bws exited 1: secret not found")
	}))
	if err == nil {
		t.Fatal("expected subprocess error to propagate")
	}
}

func TestResolveVaultRefBSMMalformedJSON(t *testing.T) {
	t.Parallel()
	cfg := vaultTestConfigBSM(t, "valid-token")
	_, err := resolveVaultRef(cfg, cfg.Profiles["bsm-fetch"], Request{
		Kind:     requestKindVault,
		Profile:  "bsm-fetch",
		Resource: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		VaultRef: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
	}, mockExecutor(t, func(ctx context.Context, bin string, args []string, env []string) ([]byte, error) {
		return []byte("not json"), nil
	}))
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("expected JSON parse error, got %v", err)
	}
}

func TestVaultOutputCappedWriter(t *testing.T) {
	t.Parallel()
	var sink strings.Builder
	w := &cappedWriter{w: &sink, cap: 5}
	if _, err := w.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "hello" {
		t.Fatalf("expected truncation to %q, got %q", "hello", sink.String())
	}
	if !w.exceeded {
		t.Fatal("exceeded flag should be set")
	}
}

func TestDefaultVaultExecutorFailsClosedOnOversizeOutput(t *testing.T) {
	t.Parallel()
	// Emit > 1 MiB on stdout via /bin/sh and assert the executor surfaces
	// an oversize error rather than returning a silently-truncated value.
	bigBytes := vaultOutputCap + 16
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := defaultVaultExecutor(
		ctx,
		"/bin/sh",
		[]string{"-c", "printf '%*s' " + itoa(bigBytes) + " ''"},
		[]string{"PATH=/bin:/usr/bin"},
	)
	if err == nil {
		t.Fatalf("expected oversize-output error, got %d bytes ok", len(out))
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected 'exceeded' in error, got %v", err)
	}
}

// --- helpers ---

func vaultTestConfigBSM(t *testing.T, tokenValue string) *Config {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "bws.token")
	if err := writeFileForTest(tokenFile, tokenValue); err != nil {
		t.Fatal(err)
	}
	trim := true
	return &Config{
		Version: configVersion,
		SecretSources: map[string]SecretSource{
			"bws_access_token": {
				Type: "file",
				File: tokenFile,
				Trim: &trim,
			},
		},
		Profiles: map[string]Profile{
			"bsm-fetch": {
				Kind:       requestKindVault,
				Vault:      "bsm",
				VaultAuth:  "bws_access_token",
				Agents:     []string{"hermes"},
				Resources:  []string{"5da84bec-9b21-4e7f-a720-b41b00cad9d5"},
				TTLSeconds: 60,
			},
		},
	}
}

func vaultTestConfigBW(t *testing.T, sessionValue string) (*Config, string) {
	t.Helper()
	dir := t.TempDir()
	sessionFile := filepath.Join(dir, "bw.session")
	if err := writeFileForTest(sessionFile, sessionValue); err != nil {
		t.Fatal(err)
	}
	trim := true
	cfg := &Config{
		Version: configVersion,
		SecretSources: map[string]SecretSource{
			"bw_session": {
				Type: "file",
				File: sessionFile,
				Trim: &trim,
			},
		},
		Profiles: map[string]Profile{
			"bw-fetch": {
				Kind:        requestKindVault,
				Vault:       "bw",
				VaultAuth:   "bw_session",
				Agents:      []string{"hermes"},
				Resources:   []string{"2captcha.com"},
				VaultFields: []string{"password", "username", "notes", "totp"},
				TTLSeconds:  60,
			},
		},
	}
	return cfg, sessionFile
}

func mockExecutor(t *testing.T, fn func(context.Context, string, []string, []string) ([]byte, error)) vaultExecutor {
	t.Helper()
	return vaultExecutor(fn)
}

func envContains(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sliceContains(a []string, want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
