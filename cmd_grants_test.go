// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

// seedAllSources writes one of each grant source into a fresh stateDir
// so the unified collector can be exercised end-to-end.
func seedAllSources(t *testing.T, now time.Time) string {
	t.Helper()
	dir := t.TempDir()

	// Operator-session grant
	if _, err := createGrant(dir, Request{
		Agent: "hermes", Profile: "k8s-read", Resource: "namespace/kestrel",
		Reason: "session reuse",
	}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	// Permanent grant
	if err := appendPermanentGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/forever",
		GrantedAt:      now.UTC(),
		GrantedBy:      "kcrawley@web",
		RequestID:      "req_perm_1",
		Reason:         "permanent test",
	}); err != nil {
		t.Fatal(err)
	}
	// Temporal grant (active)
	if err := appendTemporalGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/once",
		GrantMode:      grantModeOnce,
		GrantedAt:      now.UTC(),
		ExpiresAt:      now.Add(24 * time.Hour).UTC(),
		GrantedBy:      "kcrawley@cli",
		RequestID:      "req_temp_active",
		Reason:         "active test",
	}); err != nil {
		t.Fatal(err)
	}
	// Temporal grant (already expired)
	if err := appendTemporalGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/expired",
		GrantMode:      grantModeOnce,
		GrantedAt:      now.Add(-48 * time.Hour).UTC(),
		ExpiresAt:      now.Add(-24 * time.Hour).UTC(),
		GrantedBy:      "kcrawley@cli",
		RequestID:      "req_temp_expired",
		Reason:         "expired test",
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCollectAllGrantsReturnsAllSources(t *testing.T) {
	t.Parallel()
	now := time.Now()
	dir := seedAllSources(t, now)
	rows, err := collectAllGrants(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("expected 4 rows (1 op-session + 1 perm + 2 temp), got %d: %+v", len(rows), rows)
	}
	have := map[string]int{}
	for _, r := range rows {
		have[r.source]++
	}
	if have["operator-session"] != 1 || have["permanent"] != 1 || have["temporal"] != 2 {
		t.Fatalf("source distribution wrong: %+v", have)
	}
}

func TestCollectAllGrantsMarksExpired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	dir := seedAllSources(t, now)
	rows, err := collectAllGrants(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	expiredCount := 0
	for _, r := range rows {
		if r.expired {
			expiredCount++
		}
	}
	if expiredCount != 1 {
		t.Fatalf("expected 1 expired, got %d", expiredCount)
	}
}

func TestRenderGrantsTableContainsKeyFields(t *testing.T) {
	t.Parallel()
	now := time.Now()
	dir := seedAllSources(t, now)
	rows, err := collectAllGrants(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	renderGrantsTable(&buf, rows)
	out := buf.String()
	for _, want := range []string{
		"SOURCE", "MODE", "PROFILE", "operator-session", "permanent", "temporal",
		"namespace/forever", "namespace/once", "kcrawley@web", "kcrawley@cli",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q in:\n%s", want, out)
		}
	}
}

func TestRevokeOnePermanentRemovesByRequestID(t *testing.T) {
	t.Parallel()
	now := time.Now()
	dir := seedAllSources(t, now)
	row := listedGrant{source: "permanent", id: "req_perm_1", profile: "k8s-read", resource: "namespace/forever"}
	if err := revokeOne(dir, row, "test-op"); err != nil {
		t.Fatal(err)
	}
	perms, err := loadGrantsJSONL(permanentGrantsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range perms {
		if g.RequestID == "req_perm_1" {
			t.Fatalf("revoke didn't remove req_perm_1: %+v", perms)
		}
	}
	// Audit row landed
	auditPath := dir + "/audit.jsonl"
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "permission_upgrade_revoked") {
		t.Fatalf("audit row missing: %s", string(data))
	}
}

func TestRevokeOneTemporalRemovesByRequestID(t *testing.T) {
	t.Parallel()
	now := time.Now()
	dir := seedAllSources(t, now)
	row := listedGrant{source: "temporal", id: "req_temp_active", profile: "k8s-read", resource: "namespace/once"}
	if err := revokeOne(dir, row, "test-op"); err != nil {
		t.Fatal(err)
	}
	temps, err := loadGrantsJSONL(temporalGrantsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 1 || temps[0].RequestID != "req_temp_expired" {
		t.Fatalf("revoke didn't isolate the right entry: %+v", temps)
	}
}

func TestRevokeAllByKindPermanentTruncatesFile(t *testing.T) {
	t.Parallel()
	now := time.Now()
	dir := seedAllSources(t, now)
	if err := revokeAllByKind(dir, "permanent", "test-op"); err != nil {
		t.Fatal(err)
	}
	perms, err := loadGrantsJSONL(permanentGrantsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(perms) != 0 {
		t.Fatalf("expected 0 permanent after revoke-all, got %d", len(perms))
	}
	// Other sources untouched
	temps, _ := loadGrantsJSONL(temporalGrantsPath(dir))
	if len(temps) != 2 {
		t.Fatalf("temporal grants disturbed: %d", len(temps))
	}
}

func TestRewriteGrantsJSONLExcludeIdempotent(t *testing.T) {
	t.Parallel()
	now := time.Now()
	dir := seedAllSources(t, now)
	// id that doesn't exist anywhere — should be a no-op, not an error
	if err := rewriteGrantsJSONLExclude(permanentGrantsPath(dir), "req_does_not_exist"); err != nil {
		t.Fatal(err)
	}
	perms, err := loadGrantsJSONL(permanentGrantsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(perms) != 1 {
		t.Fatalf("idempotent path disturbed file: %+v", perms)
	}
}

func TestRevokeAllByKindUnknownErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := revokeAllByKind(dir, "garbage", "test-op"); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}
