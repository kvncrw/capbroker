// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"time"
)

func TestGrantLifecycle(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	req := Request{Agent: "codex", Profile: "github-review", Resource: "example-org/example-repo"}
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	grant, err := createGrant(stateDir, req, 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if grant.ID == "" {
		t.Fatal("grant id should be set")
	}
	active, err := activeGrant(stateDir, req, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.ID != grant.ID {
		t.Fatalf("expected active grant %s, got %#v", grant.ID, active)
	}
	active, err = activeGrant(stateDir, req, now.Add(11*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatal("expired grant should not be active")
	}
	if err := revokeGrants(stateDir, grant.ID, false); err != nil {
		t.Fatal(err)
	}
	grants, err := loadGrants(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected no grants after revoke, got %d", len(grants))
	}
}
