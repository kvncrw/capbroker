// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"
)

func TestPrepareCommandEnvMaterializesFiles(t *testing.T) {
	t.Parallel()
	env, cleanup, redactions, err := prepareCommandEnv(
		map[string]string{"GH_TOKEN": "token-value"},
		map[string]string{"KUBECONFIG": "apiVersion: v1\nclusters: []\n"},
		[]string{"existing-redaction"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if env["GH_TOKEN"] != "token-value" {
		t.Fatalf("unexpected env value %q", env["GH_TOKEN"])
	}
	kubeconfigPath := env["KUBECONFIG"]
	if kubeconfigPath == "" {
		t.Fatal("KUBECONFIG path was not set")
	}
	data, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "apiVersion: v1\nclusters: []\n" {
		t.Fatalf("unexpected file content %q", data)
	}
	info, err := os.Stat(kubeconfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected file mode %o", info.Mode().Perm())
	}
	if len(redactions) != 3 {
		t.Fatalf("expected three redactions, got %d", len(redactions))
	}
}

func TestValidateEnvName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"KUBECONFIG", "GH_TOKEN", "_CAPBROKER_1"} {
		if err := validateEnvName(name); err != nil {
			t.Fatalf("%s should be valid: %v", name, err)
		}
	}
	for _, name := range []string{"", "1BAD", "BAD-NAME", "BAD/NAME"} {
		if err := validateEnvName(name); err == nil {
			t.Fatalf("%s should be invalid", name)
		}
	}
}
