// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func TestMatchesAny(t *testing.T) {
	t.Parallel()
	if !matchesAny([]string{"example-org/*"}, "example-org/example-repo") {
		t.Fatal("expected wildcard to match")
	}
	if matchesAny([]string{"example-org/*"}, "other/example-repo") {
		t.Fatal("unexpected wildcard match")
	}
	if matchesAny(nil, "anything") {
		t.Fatal("empty policy should deny")
	}
}

func TestCommandAllowed(t *testing.T) {
	t.Parallel()
	allowed := [][]string{{"gh", "pr", "view"}, {"kubectl", "get"}}
	if !commandAllowed(allowed, []string{"gh", "pr", "view", "139"}) {
		t.Fatal("expected exact prefix to be allowed")
	}
	if !commandAllowed(allowed, []string{"kubectl", "get", "pods"}) {
		t.Fatal("expected kubectl get to be allowed")
	}
	if commandAllowed(allowed, []string{"gh", "auth", "token"}) {
		t.Fatal("unexpected command allowed")
	}
	if commandAllowed(allowed, []string{"kubectl"}) {
		t.Fatal("short command should not satisfy longer prefix")
	}
}

func TestValidateRequestDeniesByDefault(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Version: configVersion,
		Profiles: map[string]Profile{
			"github-review": {
				Agents:          []string{"codex"},
				Resources:       []string{"example-org/*"},
				TTLSeconds:      60,
				RequireApproval: true,
				AllowedCommands: [][]string{{"gh", "pr", "view"}},
			},
		},
	}
	_, err := cfg.validateRequest(Request{
		Agent:    "remote-agent",
		Profile:  "github-review",
		Resource: "example-org/example-repo",
		Command:  []string{"gh", "pr", "view", "139"},
	}, true)
	if err == nil {
		t.Fatal("expected unknown agent to be denied")
	}
	_, err = cfg.validateRequest(Request{
		Agent:    "codex",
		Profile:  "github-review",
		Resource: "example-org/example-repo",
		Command:  []string{"gh", "auth", "token"},
	}, true)
	if err == nil {
		t.Fatal("expected disallowed command to be denied")
	}
}

func TestValidateRequestVaultProfile(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Version: configVersion,
		Profiles: map[string]Profile{
			"bsm-fetch": {
				Kind:       requestKindVault,
				Vault:      "bsm",
				VaultAuth:  "bws_access_token",
				Agents:     []string{"hermes"},
				Resources:  []string{"5da84bec-9b21-4e7f-a720-b41b00cad9d5"},
				TTLSeconds: 60,
			},
			"bw-fetch": {
				Kind:        requestKindVault,
				Vault:       "bw",
				VaultAuth:   "bw_session",
				Agents:      []string{"hermes"},
				Resources:   []string{"2captcha.com"},
				VaultFields: []string{"password", "username"},
				TTLSeconds:  60,
			},
		},
	}

	// bsm: happy path with kind=vault — needsCommand=false, no command required.
	if _, err := cfg.validateRequest(Request{
		Kind:     requestKindVault,
		Agent:    "hermes",
		Profile:  "bsm-fetch",
		Resource: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		VaultRef: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
	}, false); err != nil {
		t.Fatalf("vault bsm happy-path should pass, got %v", err)
	}

	// bw: happy path with allowed field
	if _, err := cfg.validateRequest(Request{
		Kind:       requestKindVault,
		Agent:      "hermes",
		Profile:    "bw-fetch",
		Resource:   "2captcha.com",
		VaultRef:   "2captcha.com",
		VaultField: "password",
	}, false); err != nil {
		t.Fatalf("vault bw happy-path should pass, got %v", err)
	}

	// kind mismatch: profile is vault, request has empty kind (= command)
	if _, err := cfg.validateRequest(Request{
		Agent:    "hermes",
		Profile:  "bsm-fetch",
		Resource: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		VaultRef: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
	}, false); err == nil {
		t.Fatal("expected kind mismatch to be denied")
	}

	// resource not in allowlist
	if _, err := cfg.validateRequest(Request{
		Kind:     requestKindVault,
		Agent:    "hermes",
		Profile:  "bsm-fetch",
		Resource: "00000000-0000-0000-0000-000000000000",
		VaultRef: "00000000-0000-0000-0000-000000000000",
	}, false); err == nil {
		t.Fatal("expected unlisted vault ref to be denied")
	}

	// resource and vault_ref must match — defends against allowlist bypass
	// via a matching Resource paired with a different VaultRef.
	if _, err := cfg.validateRequest(Request{
		Kind:     requestKindVault,
		Agent:    "hermes",
		Profile:  "bsm-fetch",
		Resource: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		VaultRef: "00000000-0000-0000-0000-000000000000",
	}, false); err == nil {
		t.Fatal("expected resource/vault_ref mismatch to be denied")
	}

	// bw field not in allowlist
	if _, err := cfg.validateRequest(Request{
		Kind:       requestKindVault,
		Agent:      "hermes",
		Profile:    "bw-fetch",
		Resource:   "2captcha.com",
		VaultRef:   "2captcha.com",
		VaultField: "notes",
	}, false); err == nil {
		t.Fatal("expected unlisted vault_field to be denied")
	}

	// command must be empty for vault requests
	if _, err := cfg.validateRequest(Request{
		Kind:     requestKindVault,
		Agent:    "hermes",
		Profile:  "bsm-fetch",
		Resource: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		VaultRef: "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		Command:  []string{"bws", "secret", "list"},
	}, false); err == nil {
		t.Fatal("expected vault request with command to be denied")
	}

	// command profile cannot be reached with kind=vault
	cmdProfile := Config{
		Version: configVersion,
		Profiles: map[string]Profile{
			"github-review": {
				Agents:          []string{"hermes"},
				Resources:       []string{"example-org/*"},
				TTLSeconds:      60,
				AllowedCommands: [][]string{{"gh", "pr", "view"}},
			},
		},
	}
	if _, err := cmdProfile.validateRequest(Request{
		Kind:     requestKindVault,
		Agent:    "hermes",
		Profile:  "github-review",
		Resource: "example-org/example-repo",
		VaultRef: "example-org/example-repo",
	}, false); err == nil {
		t.Fatal("expected vault kind against command profile to be denied")
	}
}
