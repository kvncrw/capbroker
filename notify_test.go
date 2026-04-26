// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestNotifyPermissionUpgradeNoConfig(t *testing.T) {
	t.Parallel()
	// Notifier not configured = silent success. Operator opted out;
	// they'll discover pending requests via CLI / HTTP form.
	cfg := &Config{}
	err := notifyPermissionUpgrade(cfg, RemoteRequest{ID: "req_1"}, "https://x", nil)
	if err != nil {
		t.Fatalf("expected silent success without notify config, got %v", err)
	}
}

func TestNotifyPermissionUpgradeFiresCommandWithEnvAndStdin(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "tok")
	if err := writeFileForTest(tokenFile, "p-token-xyz"); err != nil {
		t.Fatal(err)
	}
	trim := true
	cfg := &Config{
		SecretSources: map[string]SecretSource{
			"pushover_token": {Type: "file", File: tokenFile, Trim: &trim},
		},
		Notify: NotifyConfig{
			PermissionUpgrade: &NotifyTarget{
				Type:    "command",
				Command: []string{"sh", "-c", "true"},
				SecretSources: map[string]string{
					"PUSHOVER_TOKEN": "pushover_token",
				},
				TimeoutSeconds: 5,
			},
		},
	}

	var capturedCmd []string
	var capturedEnv []string
	var capturedStdin []byte
	mock := func(ctx context.Context, command []string, env []string, stdin []byte) error {
		capturedCmd = command
		capturedEnv = env
		capturedStdin = stdin
		return nil
	}
	req := RemoteRequest{
		ID:                "req_xyz",
		Kind:              requestKindPermissionUpgrade,
		Agent:             "hermes",
		Profile:           "permission-upgrade",
		TargetProfile:     "k8s-read",
		TargetResource:    "namespace/basilisk",
		GrantMode:         grantModeOnce,
		Reason:            "screenshot mission needs API pod logs to debug missing thumbnails",
		OriginalRequestID: "req_orig",
	}
	if err := notifyPermissionUpgrade(cfg, req, "https://capbroker.crawley.systems", mock); err != nil {
		t.Fatal(err)
	}
	if !sliceEqual(capturedCmd, []string{"sh", "-c", "true"}) {
		t.Fatalf("unexpected command: %v", capturedCmd)
	}
	if !envContains(capturedEnv, "PUSHOVER_TOKEN=p-token-xyz") {
		t.Fatalf("PUSHOVER_TOKEN not propagated to env: %v", capturedEnv)
	}
	// stdin should be JSON with the request fields + URL substitution
	var body notificationBody
	if err := json.Unmarshal(capturedStdin, &body); err != nil {
		t.Fatalf("stdin not valid JSON: %v\n%s", err, capturedStdin)
	}
	if body.ID != "req_xyz" || body.TargetResource != "namespace/basilisk" || body.GrantMode != "once" {
		t.Fatalf("unexpected body: %+v", body)
	}
	if body.ApproveURL != "https://capbroker.crawley.systems/u/req_xyz" {
		t.Fatalf("approve URL wrong: %q", body.ApproveURL)
	}
	if body.DiffURL != "https://capbroker.crawley.systems/u/req_xyz/diff" {
		t.Fatalf("diff URL wrong: %q", body.DiffURL)
	}
}

func TestNotifyPermissionUpgradeMissingSourceErrors(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Notify: NotifyConfig{
			PermissionUpgrade: &NotifyTarget{
				Type:    "command",
				Command: []string{"true"},
				SecretSources: map[string]string{
					"X": "no_such_source",
				},
			},
		},
	}
	err := notifyPermissionUpgrade(cfg, RemoteRequest{ID: "x"}, "", func(ctx context.Context, c, e []string, s []byte) error {
		t.Fatal("executor should not be reached when source resolution fails")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "unknown secret source") {
		t.Fatalf("expected unknown-source error, got %v", err)
	}
}

func TestNotifyPermissionUpgradePropagatesExecutorError(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Notify: NotifyConfig{
			PermissionUpgrade: &NotifyTarget{
				Type:    "command",
				Command: []string{"true"},
			},
		},
	}
	mock := func(ctx context.Context, c, e []string, s []byte) error {
		return errors.New("pushover 503")
	}
	err := notifyPermissionUpgrade(cfg, RemoteRequest{ID: "x"}, "", mock)
	if err == nil || !strings.Contains(err.Error(), "pushover 503") {
		t.Fatalf("expected executor error, got %v", err)
	}
}

func TestNotifyPermissionUpgradeUnsupportedType(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Notify: NotifyConfig{
			PermissionUpgrade: &NotifyTarget{Type: "http"},
		},
	}
	if err := notifyPermissionUpgrade(cfg, RemoteRequest{}, "", nil); err == nil {
		t.Fatal("expected error for unsupported notify type")
	}
}
