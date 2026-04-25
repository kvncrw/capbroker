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
