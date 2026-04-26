// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MaxAutoApproveTTL is a hard cap on how long the on-disk auto-approve
// lease can be. Anything longer is rejected at enable time. Pre-mobile/SMS
// approval flow this is the only safety net — keep it conservative.
const MaxAutoApproveTTL = 30 * time.Minute

// AutoApproveLease is what's persisted under <state>/auto-approve.lease.
// It deliberately mirrors a thin slice of AuditEvent so a leaked lease
// file is enough to reconstruct who turned it on and why.
type AutoApproveLease struct {
	EnabledAt time.Time `json:"enabled_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
}

func autoApproveLeasePath(stateDir string) string {
	return filepath.Join(stateDir, "auto-approve.lease")
}

// enableAutoApprove writes a fresh lease, replacing any existing one.
// Returns the lease that was written.
func enableAutoApprove(stateDir string, ttl time.Duration, reason string) (AutoApproveLease, error) {
	if ttl <= 0 {
		return AutoApproveLease{}, errors.New("auto-approve ttl must be positive")
	}
	if ttl > MaxAutoApproveTTL {
		return AutoApproveLease{}, fmt.Errorf("auto-approve ttl %s exceeds hard cap %s", ttl, MaxAutoApproveTTL)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return AutoApproveLease{}, err
	}
	now := time.Now().UTC()
	lease := AutoApproveLease{
		EnabledAt: now,
		ExpiresAt: now.Add(ttl),
		Reason:    reason,
	}
	data, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		return AutoApproveLease{}, err
	}
	if err := os.WriteFile(autoApproveLeasePath(stateDir), data, 0o600); err != nil {
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
// lease file doesn't accumulate stale state.
func readAutoApproveLease(stateDir string, now time.Time) (AutoApproveLease, bool) {
	data, err := os.ReadFile(autoApproveLeasePath(stateDir))
	if err != nil {
		return AutoApproveLease{}, false
	}
	var lease AutoApproveLease
	if err := json.Unmarshal(data, &lease); err != nil {
		return AutoApproveLease{}, false
	}
	if !now.Before(lease.ExpiresAt) {
		_ = os.Remove(autoApproveLeasePath(stateDir))
		return lease, false
	}
	return lease, true
}
