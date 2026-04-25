// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Grant struct {
	ID          string    `json:"id"`
	Agent       string    `json:"agent"`
	Profile     string    `json:"profile"`
	Resource    string    `json:"resource"`
	Reason      string    `json:"reason"`
	RequestHash string    `json:"request_hash"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func requestHash(req Request) string {
	sum := sha256.Sum256([]byte(req.Agent + "\x00" + req.Profile + "\x00" + req.Resource))
	return hex.EncodeToString(sum[:])
}

func activeGrant(stateDir string, req Request, now time.Time) (*Grant, error) {
	grants, err := loadGrants(stateDir)
	if err != nil {
		return nil, err
	}
	hash := requestHash(req)
	for _, grant := range grants {
		if grant.RequestHash == hash && now.Before(grant.ExpiresAt) {
			return &grant, nil
		}
	}
	return nil, nil
}

func createGrant(stateDir string, req Request, ttl time.Duration, now time.Time) (Grant, error) {
	grant := Grant{
		ID:          "cap_" + randomHex(16),
		Agent:       req.Agent,
		Profile:     req.Profile,
		Resource:    req.Resource,
		Reason:      req.Reason,
		RequestHash: requestHash(req),
		CreatedAt:   now.UTC(),
		ExpiresAt:   now.Add(ttl).UTC(),
	}
	grants, err := loadGrants(stateDir)
	if err != nil {
		return Grant{}, err
	}
	grants = append(grants, grant)
	return grant, saveGrants(stateDir, pruneExpired(grants, now))
}

func loadGrants(stateDir string) ([]Grant, error) {
	path := filepath.Join(stateDir, "grants.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var grants []Grant
	if err := json.Unmarshal(data, &grants); err != nil {
		return nil, fmt.Errorf("parse grants: %w", err)
	}
	return grants, nil
}

func saveGrants(stateDir string, grants []Grant) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(stateDir, "grants.json")
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(grants, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func pruneExpired(grants []Grant, now time.Time) []Grant {
	out := grants[:0]
	for _, grant := range grants {
		if now.Before(grant.ExpiresAt) {
			out = append(out, grant)
		}
	}
	return out
}

func revokeGrants(stateDir, id string, all bool) error {
	if all {
		return saveGrants(stateDir, nil)
	}
	grants, err := loadGrants(stateDir)
	if err != nil {
		return err
	}
	out := grants[:0]
	for _, grant := range grants {
		if grant.ID != id {
			out = append(out, grant)
		}
	}
	return saveGrants(stateDir, out)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
