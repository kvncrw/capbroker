// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"
)

func TestRequestedSessionTTLCapsAtConfigAndProfile(t *testing.T) {
	t.Parallel()
	cfg := &Config{Defaults: Defaults{MaxSessionSeconds: 3 * 60 * 60}}
	profile := Profile{TTLSeconds: 900, MaxSessionSeconds: 3600}
	req := Request{SessionTTLSeconds: 8 * 60 * 60}
	if got := requestedSessionTTL(cfg, profile, req); got != time.Hour {
		t.Fatalf("expected profile cap of 1h, got %s", got)
	}
	req.SessionTTLSeconds = 0
	if got := requestedSessionTTL(cfg, profile, req); got != 15*time.Minute {
		t.Fatalf("expected profile TTL of 15m, got %s", got)
	}
}

func TestCommandCritical(t *testing.T) {
	t.Parallel()
	profile := Profile{CriticalCommands: [][]string{{"gh", "repo", "delete"}, {"kubectl", "delete"}}}
	if !requestIsCritical(profile, Request{Command: []string{"gh", "repo", "delete", "example/repo", "--yes"}}) {
		t.Fatal("expected gh repo delete to be critical")
	}
	if requestIsCritical(profile, Request{Command: []string{"gh", "repo", "view", "example/repo"}}) {
		t.Fatal("expected gh repo view to be non-critical")
	}
}

func TestLocalAuthorityReusesActiveOperatorSession(t *testing.T) {
	t.Setenv("TEST_GH_TOKEN", "secret-token")
	stateDir := t.TempDir()
	req := Request{
		Agent:    "remote-agent",
		Profile:  "github-review",
		Resource: "example-org/example-repo",
		Reason:   "inspect",
		Command:  []string{"gh", "repo", "view", "example-org/example-repo"},
	}
	if _, err := createGrant(stateDir, req, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	server := capbrokerServer{
		cfg:      operatorSessionTestConfig(false),
		stateDir: stateDir,
		store:    newRemoteStore(stateDir),
	}
	remoteReq := createStoredRemoteRequest(t, &server.store, req, publicKey)
	server.localDecideRequest(remoteReq)
	updated, ok, err := server.store.get(remoteReq.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected stored request")
	}
	if updated.Status != remoteStatusApproved {
		t.Fatalf("expected approved status, got %s: %s", updated.Status, updated.Message)
	}
	if !strings.Contains(updated.Message, "active operator session") {
		t.Fatalf("expected active-session approval message, got %q", updated.Message)
	}
	payload, err := decryptLease(privateKey, *updated.EncryptedLease)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Env["GH_TOKEN"] != "secret-token" {
		t.Fatalf("unexpected leased token %q", payload.Env["GH_TOKEN"])
	}
}

func TestCriticalRequestDoesNotReuseActiveOperatorSession(t *testing.T) {
	t.Setenv("TEST_GH_TOKEN", "secret-token")
	t.Setenv("CAPBROKER_AUTO_APPROVE", "1")
	stateDir := t.TempDir()
	req := Request{
		Agent:    "remote-agent",
		Profile:  "github-review",
		Resource: "example-org/example-repo",
		Reason:   "delete empty repo",
		Command:  []string{"gh", "repo", "delete", "example-org/example-repo", "--yes"},
	}
	if _, err := createGrant(stateDir, req, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, publicKey, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	server := capbrokerServer{
		cfg:      operatorSessionTestConfig(true),
		stateDir: stateDir,
		store:    newRemoteStore(stateDir),
	}
	remoteReq := createStoredRemoteRequest(t, &server.store, req, publicKey)
	server.localDecideRequest(remoteReq)
	updated, ok, err := server.store.get(remoteReq.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected stored request")
	}
	if updated.Status != remoteStatusApproved {
		t.Fatalf("expected approved status, got %s: %s", updated.Status, updated.Message)
	}
	if strings.Contains(updated.Message, "active operator session") {
		t.Fatalf("critical request reused operator session: %q", updated.Message)
	}
	grants, err := loadGrants(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("critical request should not create a new operator session, got %d grants", len(grants))
	}
}

func operatorSessionTestConfig(includeCritical bool) *Config {
	profile := Profile{
		Agents:          []string{"remote-agent"},
		Resources:       []string{"example-org/*"},
		TTLSeconds:      60,
		RequireApproval: true,
		AllowedCommands: [][]string{
			{"gh", "repo", "view"},
			{"gh", "repo", "delete"},
		},
		Env: map[string]string{"GH_TOKEN": "github_token"},
	}
	if includeCritical {
		profile.CriticalCommands = [][]string{{"gh", "repo", "delete"}}
	}
	return &Config{
		Defaults: Defaults{ApprovalTimeoutSeconds: 1, MaxSessionSeconds: 3 * 60 * 60},
		SecretSources: map[string]SecretSource{
			"github_token": {Type: "env", Env: "TEST_GH_TOKEN"},
		},
		Profiles: map[string]Profile{"github-review": profile},
	}
}

func createStoredRemoteRequest(t *testing.T, store *remoteStore, req Request, publicKey string) RemoteRequest {
	t.Helper()
	remoteReq, err := store.create(RemoteRequest{
		ID:                "req_" + randomHex(16),
		Agent:             req.Agent,
		Profile:           req.Profile,
		Resource:          req.Resource,
		Reason:            req.Reason,
		Command:           req.Command,
		SessionTTLSeconds: req.SessionTTLSeconds,
		ClientPublicKey:   publicKey,
		Status:            remoteStatusPending,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return remoteReq
}
