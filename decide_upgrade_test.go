// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"
)

// upgradeTestServer returns a capbrokerServer wired up enough that the
// decide path works: cfg has the meta-profile + the target profile, store
// has a pending upgrade request, stateDir is a temp dir for grant files.
func upgradeTestServer(t *testing.T) (*capbrokerServer, RemoteRequest) {
	t.Helper()
	stateDir := t.TempDir()
	storeDir := t.TempDir()
	cfg := &Config{
		Defaults: Defaults{ApprovalTimeoutSeconds: 120, MaxSessionSeconds: 3 * 3600},
		Profiles: map[string]Profile{
			"permission-upgrade": {
				Kind:       requestKindPermissionUpgrade,
				Agents:     []string{"hermes"},
				Resources:  []string{"k8s-read"},
				TTLSeconds: 60,
			},
			"k8s-read": {
				Agents:          []string{"hermes"},
				Resources:       []string{"namespace/kestrel"},
				TTLSeconds:      60,
				AllowedCommands: [][]string{{"kubectl", "get"}},
			},
		},
	}
	server := &capbrokerServer{
		cfg:      cfg,
		stateDir: stateDir,
		store:    newRemoteStore(storeDir),
	}
	_, clientPub, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	created, err := server.store.create(RemoteRequest{
		ID:                "req_pending_upgrade",
		Kind:              requestKindPermissionUpgrade,
		Agent:             "hermes",
		Profile:           "permission-upgrade",
		Resource:          "k8s-read",
		Reason:            "screenshot mission needs API pod logs to diagnose missing thumbnails",
		TargetProfile:     "k8s-read",
		TargetResource:    "namespace/basilisk",
		GrantMode:         grantModeOnce,
		OriginalRequestID: "req_orig",
		ClientPublicKey:   clientPub,
		Status:            remoteStatusPending,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, created
}

func TestDecidePermissionUpgradeOncePersistsTemporal(t *testing.T) {
	t.Parallel()
	server, req := upgradeTestServer(t)
	updated, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{
		Mode: grantModeOnce, Operator: "kcrawley",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != remoteStatusApproved {
		t.Fatalf("expected approved, got %s", updated.Status)
	}
	grants, err := loadGrantsJSONL(temporalGrantsPath(server.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 temporal grant, got %d", len(grants))
	}
	if grants[0].ExpiresAt.IsZero() {
		t.Fatal("once grant must have ExpiresAt set")
	}
	if grants[0].GrantedBy != "kcrawley" || grants[0].RequestID != req.ID {
		t.Fatalf("grant metadata wrong: %+v", grants[0])
	}
}

func TestDecidePermissionUpgradePermanentPersistsPermanent(t *testing.T) {
	t.Parallel()
	server, req := upgradeTestServer(t)
	if _, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{
		Mode: grantModePermanent, Operator: "cli",
	}); err != nil {
		t.Fatal(err)
	}
	grants, err := loadGrantsJSONL(permanentGrantsPath(server.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 permanent grant, got %d", len(grants))
	}
	if !grants[0].ExpiresAt.IsZero() {
		t.Fatal("permanent grant must not have ExpiresAt set")
	}
	// And no temporal entry should appear.
	temps, _ := loadGrantsJSONL(temporalGrantsPath(server.stateDir))
	if len(temps) != 0 {
		t.Fatal("permanent decision should not write to temporal-grants.jsonl")
	}
}

func TestDecidePermissionUpgradeSessionUsesSessionTTL(t *testing.T) {
	t.Parallel()
	server, req := upgradeTestServer(t)
	if _, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{
		Mode: grantModeSession, Operator: "cli",
	}); err != nil {
		t.Fatal(err)
	}
	grants, err := loadGrantsJSONL(temporalGrantsPath(server.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Duration(server.cfg.Defaults.MaxSessionSeconds) * time.Second
	got := time.Until(grants[0].ExpiresAt)
	// Allow 30s slop for test scheduling.
	if got < want-30*time.Second || got > want+30*time.Second {
		t.Fatalf("session grant TTL wrong: got %s, want %s", got, want)
	}
}

func TestDecidePermissionUpgradeDenyMarksDenied(t *testing.T) {
	t.Parallel()
	server, req := upgradeTestServer(t)
	updated, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{
		Mode: "deny", Operator: "cli", Message: "scope too broad",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != remoteStatusDenied {
		t.Fatalf("expected denied, got %s", updated.Status)
	}
	if updated.Message != "scope too broad" {
		t.Fatalf("denial message lost: %q", updated.Message)
	}
	// No grant files should exist.
	temps, _ := loadGrantsJSONL(temporalGrantsPath(server.stateDir))
	perms, _ := loadGrantsJSONL(permanentGrantsPath(server.stateDir))
	if len(temps)+len(perms) != 0 {
		t.Fatalf("denial wrote grants: temporal=%d permanent=%d", len(temps), len(perms))
	}
}

func TestDecidePermissionUpgradeRejectsReDecision(t *testing.T) {
	t.Parallel()
	server, req := upgradeTestServer(t)
	if _, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{Mode: grantModeOnce}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{Mode: grantModePermanent}); err == nil {
		t.Fatal("expected re-decision to fail (already approved)")
	} else if !strings.Contains(err.Error(), "already") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecidePermissionUpgradeRejectsBadMode(t *testing.T) {
	t.Parallel()
	server, req := upgradeTestServer(t)
	if _, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{Mode: "forever"}); err == nil {
		t.Fatal("expected bad mode to be rejected")
	}
}

func TestDecidePermissionUpgradeRejectsWrongKind(t *testing.T) {
	t.Parallel()
	server, _ := upgradeTestServer(t)
	// Insert a non-upgrade pending request and try to decide it.
	_, err := server.store.create(RemoteRequest{
		ID:        "req_command",
		Kind:      requestKindCommand,
		Status:    remoteStatusPending,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.decidePermissionUpgrade("req_command", upgradeDecision{Mode: grantModeOnce}); err == nil {
		t.Fatal("expected wrong-kind decision to be rejected")
	}
}

func TestDecidePermissionUpgradeGrantUnblocksRetry(t *testing.T) {
	t.Parallel()
	// End-to-end: grant via decide, then validateRequestAt sees the
	// previously-blocked resource as allowed. Closes the loop the
	// agent retry path depends on.
	server, req := upgradeTestServer(t)
	if _, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{Mode: grantModeOnce}); err != nil {
		t.Fatal(err)
	}
	// Now a fresh command request for namespace/basilisk should pass.
	if _, err := server.cfg.validateRequestAt(Request{
		Agent:    "hermes",
		Profile:  "k8s-read",
		Resource: "namespace/basilisk",
		Command:  []string{"kubectl", "get", "pods"},
	}, true, server.stateDir, time.Now()); err != nil {
		t.Fatalf("expected post-upgrade resource to be allowed, got %v", err)
	}
}
