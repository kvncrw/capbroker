// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnableAutoApproveRejectsZeroTTL(t *testing.T) {
	dir := t.TempDir()
	if _, err := enableAutoApprove(dir, 0, "test"); err == nil {
		t.Fatal("expected error for zero ttl")
	}
}

func TestEnableAutoApproveRejectsOverCap(t *testing.T) {
	dir := t.TempDir()
	if _, err := enableAutoApprove(dir, MaxAutoApproveTTL+time.Second, "test"); err == nil {
		t.Fatal("expected error for ttl over cap")
	}
}

func TestEnableAutoApproveAtCapAccepted(t *testing.T) {
	dir := t.TempDir()
	lease, err := enableAutoApprove(dir, MaxAutoApproveTTL, "test")
	if err != nil {
		t.Fatalf("expected ttl at cap to be accepted, got %v", err)
	}
	if !lease.MaxExpiresAt.After(lease.EnabledAt) {
		t.Fatalf("expected MaxExpiresAt after EnabledAt, got %v / %v", lease.EnabledAt, lease.MaxExpiresAt)
	}
	// Initial ExpiresAt should be EnabledAt + DefaultAutoApproveIdleWindow,
	// or MaxExpiresAt if idle exceeds ttl.
	if !lease.ExpiresAt.After(lease.EnabledAt) {
		t.Fatalf("expected ExpiresAt after EnabledAt, got %v / %v", lease.EnabledAt, lease.ExpiresAt)
	}
	if lease.ExpiresAt.After(lease.MaxExpiresAt) {
		t.Fatalf("expected ExpiresAt <= MaxExpiresAt, got %v > %v", lease.ExpiresAt, lease.MaxExpiresAt)
	}
	if _, err := os.Stat(filepath.Join(dir, "auto-approve.lease")); err != nil {
		t.Fatalf("expected lease file to exist, got %v", err)
	}
}

func TestEnableAutoApproveDefaultIdleClampsToTTL(t *testing.T) {
	dir := t.TempDir()
	// ttl shorter than the default idle window — initial ExpiresAt should be at MaxExpiresAt.
	lease, err := enableAutoApprove(dir, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	if !lease.ExpiresAt.Equal(lease.MaxExpiresAt) {
		t.Fatalf("expected ExpiresAt == MaxExpiresAt when idle > ttl, got %v vs %v", lease.ExpiresAt, lease.MaxExpiresAt)
	}
}

func TestReadAutoApproveLeaseActive(t *testing.T) {
	dir := t.TempDir()
	if _, err := enableAutoApprove(dir, time.Minute, "remote-session"); err != nil {
		t.Fatal(err)
	}
	lease, active := readAutoApproveLease(dir, time.Now())
	if !active {
		t.Fatal("expected active lease")
	}
	if lease.Reason != "remote-session" {
		t.Fatalf("reason mismatch: %q", lease.Reason)
	}
}

func TestReadAutoApproveLeaseExpiredRemoves(t *testing.T) {
	dir := t.TempDir()
	if _, err := enableAutoApprove(dir, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	// Pretend now is well past expiry.
	future := time.Now().Add(2 * time.Minute)
	if _, active := readAutoApproveLease(dir, future); active {
		t.Fatal("expected expired lease to read inactive")
	}
	if _, err := os.Stat(filepath.Join(dir, "auto-approve.lease")); !os.IsNotExist(err) {
		t.Fatalf("expected lease file to be removed after expiry read, got %v", err)
	}
}

func TestReadAutoApproveLeaseHonorsAbsoluteCap(t *testing.T) {
	dir := t.TempDir()
	// Manually craft a lease whose ExpiresAt is in the future but MaxExpiresAt is in the past.
	now := time.Now().UTC()
	lease := AutoApproveLease{
		EnabledAt:    now.Add(-time.Hour),
		ExpiresAt:    now.Add(time.Minute),
		MaxExpiresAt: now.Add(-time.Second),
		IdleWindow:   5 * time.Minute,
		Reason:       "synthetic",
	}
	if err := writeAutoApproveLease(dir, lease); err != nil {
		t.Fatal(err)
	}
	if _, active := readAutoApproveLease(dir, now); active {
		t.Fatal("expected lease past MaxExpiresAt to read inactive even with future ExpiresAt")
	}
}

func TestRenewAutoApproveLeaseExtends(t *testing.T) {
	dir := t.TempDir()
	if _, err := enableAutoApproveWithIdle(dir, 30*time.Minute, 5*time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	// Read once to capture initial expiry.
	initial, active := readAutoApproveLease(dir, time.Now())
	if !active {
		t.Fatal("expected initial lease active")
	}
	// Pretend 4 minutes have passed — renew should bump ExpiresAt forward.
	later := time.Now().Add(4 * time.Minute)
	renewed, changed := renewAutoApproveLease(dir, later)
	if !changed {
		t.Fatal("expected renew to bump ExpiresAt forward")
	}
	if !renewed.ExpiresAt.After(initial.ExpiresAt) {
		t.Fatalf("expected ExpiresAt to advance, got %v <= %v", renewed.ExpiresAt, initial.ExpiresAt)
	}
	if renewed.ExpiresAt.After(renewed.MaxExpiresAt) {
		t.Fatalf("renewed ExpiresAt exceeded MaxExpiresAt: %v > %v", renewed.ExpiresAt, renewed.MaxExpiresAt)
	}
}

func TestRenewAutoApproveLeaseClampsToMax(t *testing.T) {
	dir := t.TempDir()
	if _, err := enableAutoApproveWithIdle(dir, 5*time.Minute, 5*time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	// Pretend 4m59s have passed — renewal target is +5m, but cap is +5m total.
	later := time.Now().Add(4*time.Minute + 59*time.Second)
	renewed, _ := renewAutoApproveLease(dir, later)
	if renewed.ExpiresAt.After(renewed.MaxExpiresAt) {
		t.Fatalf("renew should never push past MaxExpiresAt, got %v > %v", renewed.ExpiresAt, renewed.MaxExpiresAt)
	}
}

func TestRenewAutoApproveLeaseNoOpWhenExpired(t *testing.T) {
	dir := t.TempDir()
	if _, err := enableAutoApprove(dir, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Minute)
	_, changed := renewAutoApproveLease(dir, future)
	if changed {
		t.Fatal("expected no-op renew on expired lease")
	}
}

func TestDisableAutoApproveRemovesLease(t *testing.T) {
	dir := t.TempDir()
	if _, err := enableAutoApprove(dir, time.Minute, ""); err != nil {
		t.Fatal(err)
	}
	if err := disableAutoApprove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "auto-approve.lease")); !os.IsNotExist(err) {
		t.Fatalf("expected lease removed, got %v", err)
	}
}

func TestDisableAutoApproveMissingFileNoError(t *testing.T) {
	dir := t.TempDir()
	if err := disableAutoApprove(dir); err != nil {
		t.Fatalf("disable on missing file should succeed, got %v", err)
	}
}

func TestReadAutoApproveLeaseLegacyFormat(t *testing.T) {
	// Lease files written before MaxExpiresAt landed must still load: the
	// reader treats ExpiresAt as the absolute cap when MaxExpiresAt is zero.
	dir := t.TempDir()
	now := time.Now().UTC()
	legacy := []byte(`{"enabled_at":"` + now.Format(time.RFC3339Nano) + `","expires_at":"` + now.Add(5*time.Minute).Format(time.RFC3339Nano) + `","reason":"legacy"}`)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auto-approve.lease"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	lease, active := readAutoApproveLease(dir, now)
	if !active {
		t.Fatal("expected legacy lease to load active")
	}
	if !lease.MaxExpiresAt.Equal(lease.ExpiresAt) {
		t.Fatalf("expected MaxExpiresAt synthesized to ExpiresAt for legacy lease, got %v vs %v", lease.MaxExpiresAt, lease.ExpiresAt)
	}
}
