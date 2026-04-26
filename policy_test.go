// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"
)

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

const goodReason = "screenshot mission needs API pod logs to diagnose missing thumbnails"

func TestValidatePermissionUpgradeProfile(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Version: configVersion,
		Profiles: map[string]Profile{
			"permission-upgrade": {
				Kind:       requestKindPermissionUpgrade,
				Agents:     []string{"hermes"},
				Resources:  []string{"k8s-read", "github-review"},
				TTLSeconds: 60,
			},
			"k8s-read": {
				Agents:          []string{"hermes"},
				Resources:       []string{"namespace/kestrel"},
				TTLSeconds:      60,
				AllowedCommands: [][]string{{"kubectl", "get"}},
			},
			"meta-extender": {
				Kind:       requestKindPermissionUpgrade,
				Agents:     []string{"hermes"},
				Resources:  []string{"permission-upgrade"}, // tries to allow extending the meta-profile
				TTLSeconds: 60,
			},
		},
	}

	// Happy path: ask to extend k8s-read with namespace/basilisk, mode=once.
	if _, err := cfg.validateRequest(Request{
		Kind:           requestKindPermissionUpgrade,
		Agent:          "hermes",
		Profile:        "permission-upgrade",
		Resource:       "k8s-read",
		Reason:         goodReason,
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/basilisk",
		GrantMode:      grantModeOnce,
	}, false); err != nil {
		t.Fatalf("happy path should pass, got %v", err)
	}

	// Missing target_profile.
	if _, err := cfg.validateRequest(Request{
		Kind:           requestKindPermissionUpgrade,
		Agent:          "hermes",
		Profile:        "permission-upgrade",
		Resource:       "k8s-read",
		Reason:         goodReason,
		TargetResource: "namespace/x",
		GrantMode:      grantModeOnce,
	}, false); err == nil {
		t.Fatal("expected missing target_profile to be rejected")
	}

	// Resource mismatch (Resource != TargetProfile).
	if _, err := cfg.validateRequest(Request{
		Kind:           requestKindPermissionUpgrade,
		Agent:          "hermes",
		Profile:        "permission-upgrade",
		Resource:       "k8s-read",
		Reason:         goodReason,
		TargetProfile:  "github-review", // resource and target_profile must match
		TargetResource: "kvncrw/x",
		GrantMode:      grantModeOnce,
	}, false); err == nil {
		t.Fatal("expected resource/target_profile mismatch to be rejected")
	}

	// Target profile not in meta-profile resources allowlist.
	if _, err := cfg.validateRequest(Request{
		Kind:           requestKindPermissionUpgrade,
		Agent:          "hermes",
		Profile:        "permission-upgrade",
		Resource:       "bsm-fetch", // not in resources
		Reason:         goodReason,
		TargetProfile:  "bsm-fetch",
		TargetResource: "abc",
		GrantMode:      grantModeOnce,
	}, false); err == nil {
		t.Fatal("expected unlisted target profile to be rejected")
	}

	// Self-extension blocked: meta-extender lists permission-upgrade as a target.
	if _, err := cfg.validateRequest(Request{
		Kind:           requestKindPermissionUpgrade,
		Agent:          "hermes",
		Profile:        "meta-extender",
		Resource:       "permission-upgrade",
		Reason:         goodReason,
		TargetProfile:  "permission-upgrade",
		TargetResource: "k8s-read",
		GrantMode:      grantModePermanent,
	}, false); err == nil {
		t.Fatal("expected self-extension of permission-upgrade kind to be rejected")
	}

	// Glob target_resource rejected.
	for _, glob := range []string{"namespace/*", "ns?", "abc[def]"} {
		if _, err := cfg.validateRequest(Request{
			Kind:           requestKindPermissionUpgrade,
			Agent:          "hermes",
			Profile:        "permission-upgrade",
			Resource:       "k8s-read",
			Reason:         goodReason,
			TargetProfile:  "k8s-read",
			TargetResource: glob,
			GrantMode:      grantModeOnce,
		}, false); err == nil {
			t.Fatalf("expected glob target_resource %q to be rejected", glob)
		}
	}

	// Reason too short.
	if _, err := cfg.validateRequest(Request{
		Kind:           requestKindPermissionUpgrade,
		Agent:          "hermes",
		Profile:        "permission-upgrade",
		Resource:       "k8s-read",
		Reason:         strings.Repeat("x", 10),
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/y",
		GrantMode:      grantModeOnce,
	}, false); err == nil {
		t.Fatal("expected too-short reason to be rejected")
	}

	// Bad grant mode.
	if _, err := cfg.validateRequest(Request{
		Kind:           requestKindPermissionUpgrade,
		Agent:          "hermes",
		Profile:        "permission-upgrade",
		Resource:       "k8s-read",
		Reason:         goodReason,
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/y",
		GrantMode:      "forever",
	}, false); err == nil {
		t.Fatal("expected unknown grant_mode to be rejected")
	}

	// Command must be empty for upgrade requests.
	if _, err := cfg.validateRequest(Request{
		Kind:           requestKindPermissionUpgrade,
		Agent:          "hermes",
		Profile:        "permission-upgrade",
		Resource:       "k8s-read",
		Reason:         goodReason,
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/y",
		GrantMode:      grantModeOnce,
		Command:        []string{"kubectl", "delete", "pod", "x"},
	}, false); err == nil {
		t.Fatal("expected command on upgrade request to be rejected")
	}
}

func TestValidateRequestAtUsesDynamicGrants(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := &Config{
		Version: configVersion,
		Profiles: map[string]Profile{
			"k8s-read": {
				Agents:          []string{"hermes"},
				Resources:       []string{"namespace/kestrel"}, // namespace/basilisk NOT static-listed
				TTLSeconds:      60,
				AllowedCommands: [][]string{{"kubectl", "get"}},
			},
		},
	}
	now := time.Now().UTC()

	// Without grants, namespace/basilisk is denied.
	if _, err := cfg.validateRequestAt(Request{
		Agent:    "hermes",
		Profile:  "k8s-read",
		Resource: "namespace/basilisk",
		Command:  []string{"kubectl", "get", "pods"},
	}, true, dir, now); err == nil {
		t.Fatal("expected namespace/basilisk to be denied without a grant")
	}

	// Add a permanent grant.
	if err := appendPermanentGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/basilisk",
		GrantedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}

	// Now it should pass.
	if _, err := cfg.validateRequestAt(Request{
		Agent:    "hermes",
		Profile:  "k8s-read",
		Resource: "namespace/basilisk",
		Command:  []string{"kubectl", "get", "pods"},
	}, true, dir, now); err != nil {
		t.Fatalf("expected granted resource to be allowed, got %v", err)
	}

	// Plain validateRequest (no stateDir) should still deny — confirms the
	// dynamic extension is opt-in via validateRequestAt, not a global change.
	if _, err := cfg.validateRequest(Request{
		Agent:    "hermes",
		Profile:  "k8s-read",
		Resource: "namespace/basilisk",
		Command:  []string{"kubectl", "get", "pods"},
	}, true); err == nil {
		t.Fatal("validateRequest (no stateDir) should not honor dynamic grants")
	}
}
