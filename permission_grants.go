// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Permission grants live in two append-only JSONL files alongside the
// existing daemon state, complementing the static Profile.Resources lists
// in config.json. The operator's config.json stays canonical; capbroker-
// managed grants live separately so the operator can `cat`, `jq`, or `rm`
// them without YAML/JSON-mutation ceremony.
//
//   <state>/permanent-grants.jsonl  — survives daemon restart, rm to revoke
//   <state>/temporal-grants.jsonl   — has expires_at; pruned on read
//
// `effectiveResources(profileName)` returns the union of:
//   1. profile.Resources (static)
//   2. permanent-grants.jsonl entries for profileName
//   3. non-expired temporal-grants.jsonl entries for profileName
//
// Concurrent writers are serialized via a sibling .lock file (flock),
// matching the auto-approve lease pattern in auto_approve.go.

type permissionGrant struct {
	TargetProfile  string    `json:"target_profile"`
	TargetResource string    `json:"target_resource"`
	GrantMode      string    `json:"grant_mode"`
	GrantedAt      time.Time `json:"granted_at"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`  // temporal only
	GrantedBy      string    `json:"granted_by,omitempty"`  // operator identifier (e.g. "kcrawley")
	RequestID      string    `json:"request_id,omitempty"`  // upgrade request that created the grant
	Reason         string    `json:"reason,omitempty"`      // copied from the upgrade request
}

func permanentGrantsPath(stateDir string) string {
	return filepath.Join(stateDir, "permanent-grants.jsonl")
}

func temporalGrantsPath(stateDir string) string {
	return filepath.Join(stateDir, "temporal-grants.jsonl")
}

// appendPermanentGrant appends a grant to permanent-grants.jsonl under
// flock-serialized write. Caller is responsible for setting the GrantMode,
// GrantedAt, and not setting ExpiresAt (zero == permanent).
func appendPermanentGrant(stateDir string, g permissionGrant) error {
	g.GrantMode = grantModePermanent
	g.ExpiresAt = time.Time{} // explicitly zero
	return appendGrantJSONL(permanentGrantsPath(stateDir), g)
}

// appendTemporalGrant appends a grant to temporal-grants.jsonl with a
// non-zero ExpiresAt. Mode is either "once" or "session".
func appendTemporalGrant(stateDir string, g permissionGrant) error {
	if g.ExpiresAt.IsZero() {
		return fmt.Errorf("temporal grant requires non-zero ExpiresAt")
	}
	if g.GrantMode != grantModeOnce && g.GrantMode != grantModeSession {
		return fmt.Errorf("temporal grant requires grant_mode in {once, session}, got %q", g.GrantMode)
	}
	return appendGrantJSONL(temporalGrantsPath(stateDir), g)
}

func appendGrantJSONL(path string, g permissionGrant) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := lockGrantsFile(path)
	if err != nil {
		return err
	}
	defer unlock()
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func lockGrantsFile(path string) (func(), error) {
	lockPath := path + ".lock"
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

// loadGrantsJSONL reads all entries from a JSONL file. Missing file is
// treated as no grants (not an error). Bad lines are skipped with a
// stderr warning so a corrupt single line never bricks the daemon.
func loadGrantsJSONL(path string) ([]permissionGrant, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []permissionGrant
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var g permissionGrant
		if err := json.Unmarshal([]byte(line), &g); err != nil {
			fmt.Fprintf(os.Stderr, "capbroker: skipping malformed grant in %s: %v\n", path, err)
			continue
		}
		out = append(out, g)
	}
	return out, sc.Err()
}

// effectiveResources joins the static Profile.Resources list with any
// permanent + non-expired temporal grants for that profile. Used by
// validateRequest to extend the allowlist at runtime without touching
// config.json.
//
// Concurrent reads are safe; the JSONL files are append-only and the
// flock only protects writes.
func effectiveResources(stateDir string, profileName string, baseResources []string, now time.Time) []string {
	out := make([]string, 0, len(baseResources)+8)
	out = append(out, baseResources...)

	if perms, err := loadGrantsJSONL(permanentGrantsPath(stateDir)); err == nil {
		for _, g := range perms {
			if g.TargetProfile == profileName {
				out = append(out, g.TargetResource)
			}
		}
	}
	if temps, err := loadGrantsJSONL(temporalGrantsPath(stateDir)); err == nil {
		for _, g := range temps {
			if g.TargetProfile != profileName {
				continue
			}
			if !g.ExpiresAt.IsZero() && now.After(g.ExpiresAt) {
				continue
			}
			out = append(out, g.TargetResource)
		}
	}
	return out
}

// pruneTemporalGrants rewrites temporal-grants.jsonl with only
// non-expired entries. Idempotent. Safe to run periodically; not
// required for correctness (effectiveResources already filters at
// read time) but keeps the file small over time.
func pruneTemporalGrants(stateDir string, now time.Time) error {
	path := temporalGrantsPath(stateDir)
	unlock, err := lockGrantsFile(path)
	if err != nil {
		return err
	}
	defer unlock()
	all, err := loadGrantsJSONL(path)
	if err != nil {
		return err
	}
	var keep []permissionGrant
	for _, g := range all {
		if g.ExpiresAt.IsZero() || now.Before(g.ExpiresAt) {
			keep = append(keep, g)
		}
	}
	if len(keep) == len(all) {
		return nil // nothing to prune
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "temporal-grants.*.tmp")
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(tmp)
	for _, g := range keep {
		data, err := json.Marshal(g)
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return err
		}
		if _, err := bw.Write(append(data, '\n')); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// reasonDedupCache is a small in-memory window guarding against an
// agent firing the same upgrade reason twice in rapid succession. Keyed
// by sha-of-(agent|target_profile|target_resource|reason). Entries
// older than dedupWindow are pruned at insertion time.
type reasonDedupCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

const dedupWindow = 5 * time.Minute

func newReasonDedupCache() *reasonDedupCache {
	return &reasonDedupCache{entries: make(map[string]time.Time)}
}

// markIfFresh returns true if the key has not been seen within the
// window (and records it as seen now). Returns false if it's a dup.
func (c *reasonDedupCache) markIfFresh(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// prune
	for k, t := range c.entries {
		if now.Sub(t) > dedupWindow {
			delete(c.entries, k)
		}
	}
	if t, ok := c.entries[key]; ok && now.Sub(t) <= dedupWindow {
		return false
	}
	c.entries[key] = now
	return true
}

// rateLimiter enforces an N-per-hour cap per agent on permission-upgrade
// requests. In-memory ring; daemon restart resets the counters (acceptable
// — daemon restart is the operator's escape hatch from a stuck rate-limit).
type rateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	limit   int
	history map[string][]time.Time // agent -> request timestamps within window
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		window:  window,
		limit:   limit,
		history: make(map[string][]time.Time),
	}
}

// allow returns (true, 0) if the agent has remaining quota, or
// (false, retryAfter) if not. retryAfter is the duration until the
// oldest timestamp in the window expires.
func (r *rateLimiter) allow(agent string, now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-r.window)
	hist := r.history[agent]
	// Drop entries older than the window.
	kept := hist[:0]
	for _, t := range hist {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.limit {
		// retry-after = how long until kept[0] falls out of the window
		return false, kept[0].Sub(cutoff)
	}
	kept = append(kept, now)
	r.history[agent] = kept
	return true, 0
}
