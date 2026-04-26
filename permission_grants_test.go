// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAppendAndLoadPermanentGrant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	g := permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/basilisk",
		GrantedAt:      time.Now().UTC(),
		GrantedBy:      "kcrawley",
		RequestID:      "req_abc",
		Reason:         "test reason at least thirty chars long",
	}
	if err := appendPermanentGrant(dir, g); err != nil {
		t.Fatal(err)
	}
	got, err := loadGrantsJSONL(permanentGrantsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(got))
	}
	if got[0].TargetResource != "namespace/basilisk" {
		t.Fatalf("unexpected resource %q", got[0].TargetResource)
	}
	if got[0].GrantMode != grantModePermanent {
		t.Fatalf("permanent grant should have mode=%s, got %s", grantModePermanent, got[0].GrantMode)
	}
	if !got[0].ExpiresAt.IsZero() {
		t.Fatal("permanent grant must not have ExpiresAt set")
	}
}

func TestAppendTemporalGrantRejectsZeroExpiry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	err := appendTemporalGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/basilisk",
		GrantMode:      grantModeOnce,
	})
	if err == nil {
		t.Fatal("expected error for zero expiry")
	}
}

func TestAppendTemporalGrantRejectsBadMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	err := appendTemporalGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/basilisk",
		GrantMode:      grantModePermanent, // wrong file
		ExpiresAt:      time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("expected error for permanent mode in temporal store")
	}
}

func TestEffectiveResourcesUnion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Now().UTC()
	// permanent: namespace/basilisk
	if err := appendPermanentGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/basilisk",
		GrantedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}
	// temporal-active: namespace/monitoring (expires in 1h)
	if err := appendTemporalGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/monitoring",
		GrantMode:      grantModeOnce,
		GrantedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// temporal-expired: namespace/expired (expired 1h ago, must be filtered)
	if err := appendTemporalGrant(dir, permissionGrant{
		TargetProfile:  "k8s-read",
		TargetResource: "namespace/expired",
		GrantMode:      grantModeOnce,
		GrantedAt:      now.Add(-2 * time.Hour),
		ExpiresAt:      now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// different-profile permanent: should not appear in k8s-read result
	if err := appendPermanentGrant(dir, permissionGrant{
		TargetProfile:  "github-review",
		TargetResource: "kvncrw/other",
		GrantedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}

	got := effectiveResources(dir, "k8s-read", []string{"namespace/kestrel"}, now)
	want := map[string]bool{
		"namespace/kestrel":    true, // static
		"namespace/basilisk":   true, // permanent
		"namespace/monitoring": true, // temporal-active
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d resources, got %v", len(want), got)
	}
	for _, r := range got {
		if !want[r] {
			t.Fatalf("unexpected resource %q in result %v", r, got)
		}
	}
	// Confirm expired and other-profile entries are excluded.
	for _, r := range got {
		if r == "namespace/expired" {
			t.Fatal("expired temporal grant leaked into result")
		}
		if r == "kvncrw/other" {
			t.Fatal("other-profile grant leaked into result")
		}
	}
}

func TestEffectiveResourcesMissingFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir() // no grants written
	got := effectiveResources(dir, "k8s-read", []string{"namespace/kestrel"}, time.Now())
	if len(got) != 1 || got[0] != "namespace/kestrel" {
		t.Fatalf("expected just static resource, got %v", got)
	}
}

func TestPruneTemporalGrants(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Now().UTC()
	for _, ttl := range []time.Duration{time.Hour, -time.Hour, 2 * time.Hour, -2 * time.Hour} {
		if err := appendTemporalGrant(dir, permissionGrant{
			TargetProfile:  "k8s-read",
			TargetResource: "namespace/" + ttl.String(),
			GrantMode:      grantModeOnce,
			GrantedAt:      now,
			ExpiresAt:      now.Add(ttl),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneTemporalGrants(dir, now); err != nil {
		t.Fatal(err)
	}
	got, err := loadGrantsJSONL(temporalGrantsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 non-expired grants after prune, got %d", len(got))
	}
}

func TestAppendGrantConcurrentSafe(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = appendPermanentGrant(dir, permissionGrant{
				TargetProfile:  "k8s-read",
				TargetResource: filepath.Join("namespace", "ns"+itoa(i)),
				GrantedAt:      time.Now(),
			})
		}()
	}
	wg.Wait()
	got, err := loadGrantsJSONL(permanentGrantsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Fatalf("expected %d grants, got %d (writes lost or interleaved)", n, len(got))
	}
}

func TestReasonDedupCache(t *testing.T) {
	t.Parallel()
	c := newReasonDedupCache()
	now := time.Now()
	if !c.markIfFresh("k1", now) {
		t.Fatal("first mark should be fresh")
	}
	if c.markIfFresh("k1", now.Add(time.Second)) {
		t.Fatal("second mark within window should be dup")
	}
	// Past the window — pruning lets the key be fresh again.
	if !c.markIfFresh("k1", now.Add(dedupWindow+time.Second)) {
		t.Fatal("after window, key should be fresh")
	}
}

func TestRateLimiter(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(3, time.Hour)
	now := time.Now()
	for i := 0; i < 3; i++ {
		ok, _ := rl.allow("hermes", now.Add(time.Duration(i)*time.Minute))
		if !ok {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}
	ok, retry := rl.allow("hermes", now.Add(4*time.Minute))
	if ok {
		t.Fatal("4th call should be rate-limited")
	}
	if retry <= 0 {
		t.Fatal("retry-after should be positive")
	}
	// Different agent: independent quota.
	ok, _ = rl.allow("other", now.Add(4*time.Minute))
	if !ok {
		t.Fatal("other agent should have own quota")
	}
	// After window, original agent has quota again.
	ok, _ = rl.allow("hermes", now.Add(time.Hour+time.Minute))
	if !ok {
		t.Fatal("after window, agent should have quota")
	}
}
