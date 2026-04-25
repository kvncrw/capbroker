// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSecretSourceEnvAndRedact(t *testing.T) {
	t.Setenv("CAPBROKER_TEST_SECRET", "super-secret-token")
	value, err := resolveSecretSource(&Config{}, SecretSource{Type: "env", Env: "CAPBROKER_TEST_SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "super-secret-token" {
		t.Fatalf("unexpected value %q", value)
	}
	line := redact("token=super-secret-token", []string{value})
	if line != "token=[REDACTED]" {
		t.Fatalf("unexpected redaction %q", line)
	}
}

func TestResolveSecretSourceFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := resolveSecretSource(&Config{}, SecretSource{Type: "file", File: path})
	if err != nil {
		t.Fatal(err)
	}
	if value != "file-secret" {
		t.Fatalf("unexpected value %q", value)
	}
}

func TestResolveSecretSourceProviderCommand(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	providerPath := filepath.Join(dir, "provider")
	script := `#!/bin/sh
input=$(cat)
case "$input" in
  *'"ref":"vault/item"'*) printf 'provider-secret\n' ;;
  *) printf 'unexpected input: %s\n' "$input" >&2; exit 2 ;;
esac
`
	if err := os.WriteFile(providerPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		SecretProviders: map[string]SecretProvider{
			"test": {Type: "command", Command: []string{providerPath}},
		},
	}
	value, err := resolveSecretSource(cfg, SecretSource{Type: "provider", Provider: "test", Ref: "vault/item"})
	if err != nil {
		t.Fatal(err)
	}
	if value != "provider-secret" {
		t.Fatalf("unexpected value %q", value)
	}
}

func TestResolveProfileSecretsFileEnv(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		SecretSources: map[string]SecretSource{
			"kubeconfig": {Type: "command", Command: []string{"printf", "apiVersion: v1\n"}},
		},
	}
	secrets, err := resolveProfileSecrets(cfg, Profile{Files: map[string]string{"KUBECONFIG": "kubeconfig"}})
	if err != nil {
		t.Fatal(err)
	}
	if secrets.Files["KUBECONFIG"] != "apiVersion: v1" {
		t.Fatalf("unexpected file content %q", secrets.Files["KUBECONFIG"])
	}
}

func TestSecretSourceHintSuffix(t *testing.T) {
	t.Parallel()
	source := SecretSource{Hint: "run the setup command"}
	if got := secretSourceHintSuffix(source); got != "; hint: run the setup command" {
		t.Fatalf("unexpected hint suffix %q", got)
	}
	if got := secretSourceHintSuffix(SecretSource{}); got != "" {
		t.Fatalf("unexpected empty hint suffix %q", got)
	}
}
