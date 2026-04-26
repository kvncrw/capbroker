// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// MaxAutoApproveTTL is the hard absolute cap from the moment the lease is
// enabled. Even with continuous activity, the lease cannot live longer than
// this — pre-mobile/SMS approval, this is the only safety net.
const MaxAutoApproveTTL = 30 * time.Minute

// DefaultAutoApproveIdleWindow is how long the lease stays alive between
// approved requests. Each use bumps ExpiresAt to now+IdleWindow, capped by
// MaxExpiresAt. Means: enable once, requests keep it on, idle = expires fast.
const DefaultAutoApproveIdleWindow = 5 * time.Minute

// AutoApproveLease is what's persisted under <state>/auto-approve.lease.
// It deliberately mirrors a thin slice of AuditEvent so a leaked lease
// file is enough to reconstruct who turned it on and why.
type AutoApproveLease struct {
	EnabledAt    time.Time     `json:"enabled_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	MaxExpiresAt time.Time     `json:"max_expires_at"`
	IdleWindow   time.Duration `json:"idle_window_ns,omitempty"`
	Reason       string        `json:"reason,omitempty"`
}

func autoApproveLeasePath(stateDir string) string {
	return filepath.Join(stateDir, "auto-approve.lease")
}

// enableAutoApprove writes a fresh lease, replacing any existing one.
// idleWindow is how long the lease stays alive between successful requests;
// when zero, DefaultAutoApproveIdleWindow is used. ttl is the absolute
// hard ceiling — the lease cannot live longer than that from enable time,
// regardless of how much activity is renewing it.
func enableAutoApprove(stateDir string, ttl time.Duration, reason string) (AutoApproveLease, error) {
	return enableAutoApproveWithIdle(stateDir, ttl, 0, reason)
}

func enableAutoApproveWithIdle(stateDir string, ttl, idleWindow time.Duration, reason string) (AutoApproveLease, error) {
	if ttl <= 0 {
		return AutoApproveLease{}, errors.New("auto-approve ttl must be positive")
	}
	if ttl > MaxAutoApproveTTL {
		return AutoApproveLease{}, fmt.Errorf("auto-approve ttl %s exceeds hard cap %s", ttl, MaxAutoApproveTTL)
	}
	if idleWindow <= 0 {
		idleWindow = DefaultAutoApproveIdleWindow
	}
	if idleWindow > ttl {
		idleWindow = ttl
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return AutoApproveLease{}, err
	}
	now := time.Now().UTC()
	maxExpires := now.Add(ttl)
	initialExpires := now.Add(idleWindow)
	if initialExpires.After(maxExpires) {
		initialExpires = maxExpires
	}
	lease := AutoApproveLease{
		EnabledAt:    now,
		ExpiresAt:    initialExpires,
		MaxExpiresAt: maxExpires,
		IdleWindow:   idleWindow,
		Reason:       reason,
	}
	if err := writeAutoApproveLease(stateDir, lease); err != nil {
		return AutoApproveLease{}, err
	}
	return lease, nil
}

// disableAutoApprove removes the lease file. Missing-file is not an error.
func disableAutoApprove(stateDir string) error {
	err := os.Remove(autoApproveLeasePath(stateDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// readAutoApproveLease returns (lease, true) if a non-expired lease exists,
// else (zero, false). Expired leases are removed as a side-effect so the
// lease file doesn't accumulate stale state. Reads MaxExpiresAt for legacy
// leases that were written before rolling-renew shipped.
func readAutoApproveLease(stateDir string, now time.Time) (AutoApproveLease, bool) {
	data, err := os.ReadFile(autoApproveLeasePath(stateDir))
	if err != nil {
		return AutoApproveLease{}, false
	}
	var lease AutoApproveLease
	if err := json.Unmarshal(data, &lease); err != nil {
		return AutoApproveLease{}, false
	}
	if lease.MaxExpiresAt.IsZero() {
		// Legacy lease without MaxExpiresAt: treat ExpiresAt as the absolute cap.
		lease.MaxExpiresAt = lease.ExpiresAt
	}
	if !now.Before(lease.ExpiresAt) || !now.Before(lease.MaxExpiresAt) {
		_ = os.Remove(autoApproveLeasePath(stateDir))
		return lease, false
	}
	return lease, true
}

// renewAutoApproveLease bumps ExpiresAt forward to now+IdleWindow, capped
// at MaxExpiresAt. Returns the renewed lease and whether anything changed.
// A no-op if the lease is already expired or already at the absolute cap.
//
// Read-modify-write is serialized via flock on a sibling .lock file so
// concurrent renewals (multiple in-flight remote requests under one
// auto-approve session) cannot race and clobber each other's bumps —
// otherwise a writer with a stale `now` could overwrite a fresher
// ExpiresAt and effectively shorten the lease.
func renewAutoApproveLease(stateDir string, now time.Time) (AutoApproveLease, bool) {
	unlock, err := lockAutoApproveLease(stateDir)
	if err != nil {
		// If we can't acquire the lock (filesystem error, missing dir),
		// fall back to lockless behavior — better than failing closed.
		return renewAutoApproveLeaseUnsafe(stateDir, now)
	}
	defer unlock()
	return renewAutoApproveLeaseUnsafe(stateDir, now)
}

func renewAutoApproveLeaseUnsafe(stateDir string, now time.Time) (AutoApproveLease, bool) {
	lease, active := readAutoApproveLease(stateDir, now)
	if !active {
		return lease, false
	}
	idle := lease.IdleWindow
	if idle <= 0 {
		idle = DefaultAutoApproveIdleWindow
	}
	target := now.Add(idle)
	if target.After(lease.MaxExpiresAt) {
		target = lease.MaxExpiresAt
	}
	if !target.After(lease.ExpiresAt) {
		// Either we hit the cap or the bump would be backwards.
		return lease, false
	}
	lease.ExpiresAt = target
	if err := writeAutoApproveLease(stateDir, lease); err != nil {
		// On write failure, return the old lease but report no change.
		return lease, false
	}
	return lease, true
}

// lockAutoApproveLease acquires an exclusive flock on a sibling .lock file
// so concurrent renewers serialize. The returned func releases the lock
// and closes the fd.
func lockAutoApproveLease(stateDir string) (func(), error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	lockPath := autoApproveLeasePath(stateDir) + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func writeAutoApproveLease(stateDir string, lease AutoApproveLease) error {
	data, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(autoApproveLeasePath(stateDir), data, 0o600)
}
