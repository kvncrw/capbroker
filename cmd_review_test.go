// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// reviewE2EServer wires both the existing /v1/requests routes (so the
// CLI's create + poll path works) AND the /v1/upgrades/ decide route
// (so postUpgradeDecision lands). Mirrors how StartRemoteServer mounts
// them at runtime.
func reviewE2EServer(t *testing.T) (*httptest.Server, *capbrokerServer) {
	t.Helper()
	server, _ := upgradeTestServer(t)
	server.localApprove = true // /v1/requests upgrade path requires it
	// PR #12 added a fail-closed auth gate: if UpgradeApprovers is empty
	// AND AllowAnonymousUpgrade is false, all decisions return 403.
	// The CLI tests below send the operator email "kcrawley@cli" via
	// the trusted header; allowlist it so the decide path runs.
	server.cfg.Remote.UpgradeApprovers = []string{"kcrawley@cli"}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/requests", server.handleRequests)
	mux.HandleFunc("/v1/requests/", server.handleRequestByID)
	mux.HandleFunc("/v1/upgrades/", server.handleUpgradeAPI)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, server
}

func TestRunRequestUpgradeApprovesAndExitsZero(t *testing.T) {
	t.Parallel()
	ts, server := reviewE2EServer(t)

	// The fixture pre-seeds a pending req; for this test we want the CLI
	// to create its own. Decide the fixture out of the way first so the
	// list doesn't see two pending entries (which would still work, but
	// muddies the test).
	if _, err := server.decidePermissionUpgrade("req_pending_upgrade", upgradeDecision{
		Mode: grantModeOnce, Operator: "test-setup",
	}); err != nil {
		t.Fatal(err)
	}

	// Background: an operator decides the new request after a short delay
	// so the polling loop sees a transition. Find the new request by
	// polling the store.
	done := make(chan int, 1)
	go func() {
		req := Request{
			Kind:           requestKindPermissionUpgrade,
			Agent:          "hermes",
			Profile:        "permission-upgrade",
			Resource:       "k8s-read",
			Reason:         "screenshot mission needs API pod logs to diagnose missing thumbnails",
			TargetProfile:  "k8s-read",
			TargetResource: "namespace/basilisk",
			GrantMode:      grantModeOnce,
		}
		done <- runRequestUpgrade(ts.URL, req, 5*time.Second, 50*time.Millisecond)
	}()

	// Poll the store until the CLI's POST lands as pending, then approve it.
	deadline := time.Now().Add(3 * time.Second)
	var newReqID string
	for time.Now().Before(deadline) {
		all, _ := server.store.list()
		for _, r := range all {
			if r.ID != "req_pending_upgrade" && r.Kind == requestKindPermissionUpgrade && r.Status == remoteStatusPending {
				newReqID = r.ID
				break
			}
		}
		if newReqID != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if newReqID == "" {
		t.Fatal("CLI never created its request")
	}
	if _, err := server.decidePermissionUpgrade(newReqID, upgradeDecision{
		Mode: grantModeOnce, Operator: "test-operator",
	}); err != nil {
		t.Fatal(err)
	}

	exit := <-done
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d", exit)
	}
}

func TestRunRequestUpgradeDeniedExitsOne(t *testing.T) {
	t.Parallel()
	ts, server := reviewE2EServer(t)
	if _, err := server.decidePermissionUpgrade("req_pending_upgrade", upgradeDecision{
		Mode: grantModeOnce, Operator: "test-setup",
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		req := Request{
			Kind:           requestKindPermissionUpgrade,
			Agent:          "hermes",
			Profile:        "permission-upgrade",
			Resource:       "k8s-read",
			Reason:         "screenshot mission needs API pod logs to diagnose missing thumbnails",
			TargetProfile:  "k8s-read",
			TargetResource: "namespace/basilisk",
			GrantMode:      grantModeOnce,
		}
		done <- runRequestUpgrade(ts.URL, req, 5*time.Second, 50*time.Millisecond)
	}()
	deadline := time.Now().Add(3 * time.Second)
	var newReqID string
	for time.Now().Before(deadline) {
		all, _ := server.store.list()
		for _, r := range all {
			if r.ID != "req_pending_upgrade" && r.Kind == requestKindPermissionUpgrade && r.Status == remoteStatusPending {
				newReqID = r.ID
				break
			}
		}
		if newReqID != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if newReqID == "" {
		t.Fatal("CLI never created its request")
	}
	if _, err := server.decidePermissionUpgrade(newReqID, upgradeDecision{
		Mode: "deny", Operator: "test-operator", Message: "scope too broad",
	}); err != nil {
		t.Fatal(err)
	}
	if exit := <-done; exit != 1 {
		t.Fatalf("expected exit 1 on denial, got %d", exit)
	}
}

func TestUpgradeChoiceToModeMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, requested, want string
	}{
		{"a", grantModeOnce, grantModeOnce},
		{"a", grantModeSession, grantModeSession},
		{"o", "ignored", grantModeOnce},
		{"once", "ignored", grantModeOnce},
		{"s", "ignored", grantModeSession},
		{"p", "ignored", grantModePermanent},
		{"d", "ignored", "deny"},
		{"deny", "ignored", "deny"},
		{"x", grantModeOnce, ""},
		{"", grantModeOnce, ""},
	}
	for _, c := range cases {
		if got := upgradeChoiceToMode(c.in, c.requested); got != c.want {
			t.Errorf("upgradeChoiceToMode(%q, %q) = %q, want %q", c.in, c.requested, got, c.want)
		}
	}
}

func TestPromptUpgradeChoiceQuit(t *testing.T) {
	t.Parallel()
	r := bufio.NewReader(strings.NewReader("q\n"))
	choice, ok := promptUpgradeChoice(r)
	if ok {
		t.Fatalf("q should set ok=false; got choice=%q ok=%v", choice, ok)
	}
}

func TestPromptUpgradeChoiceEOF(t *testing.T) {
	t.Parallel()
	r := bufio.NewReader(strings.NewReader(""))
	if _, ok := promptUpgradeChoice(r); ok {
		t.Fatal("EOF should set ok=false")
	}
}

func TestFetchPendingUpgradesFiltersByKindAndStatus(t *testing.T) {
	t.Parallel()
	ts, server := reviewE2EServer(t)
	// Add a non-upgrade request that should be filtered out.
	if _, err := server.store.create(RemoteRequest{
		ID:        "req_command",
		Kind:      requestKindCommand,
		Status:    remoteStatusPending,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := fetchPendingUpgrades(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending upgrade, got %d: %+v", len(pending), pending)
	}
	if pending[0].ID != "req_pending_upgrade" {
		t.Fatalf("wrong request: %+v", pending[0])
	}
}

func TestPostUpgradeDecisionForwardsOperatorHeader(t *testing.T) {
	t.Parallel()
	ts, server := reviewE2EServer(t)
	updated, err := postUpgradeDecision(ts.URL, "req_pending_upgrade", grantModeOnce, "from cli", "kcrawley@cli")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != remoteStatusApproved {
		t.Fatalf("status %s", updated.Status)
	}
	grants, err := loadGrantsJSONL(temporalGrantsPath(server.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].GrantedBy != "kcrawley@cli" {
		t.Fatalf("operator header not forwarded: %+v", grants)
	}
}
