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
	if !lease.ExpiresAt.After(lease.EnabledAt) {
		t.Fatalf("expected ExpiresAt after EnabledAt, got %v / %v", lease.EnabledAt, lease.ExpiresAt)
	}
	if _, err := os.Stat(filepath.Join(dir, "auto-approve.lease")); err != nil {
		t.Fatalf("expected lease file to exist, got %v", err)
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
