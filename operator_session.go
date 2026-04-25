// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"
)

const defaultMaxOperatorSession = 3 * time.Hour

func requestedSessionTTL(cfg *Config, profile Profile, req Request) time.Duration {
	capTTL := defaultMaxOperatorSession
	if cfg != nil && cfg.Defaults.MaxSessionSeconds > 0 {
		capTTL = time.Duration(cfg.Defaults.MaxSessionSeconds) * time.Second
	}
	if profile.MaxSessionSeconds > 0 {
		profileCap := time.Duration(profile.MaxSessionSeconds) * time.Second
		if profileCap < capTTL {
			capTTL = profileCap
		}
	}
	ttl := time.Duration(profile.TTLSeconds) * time.Second
	if req.SessionTTLSeconds > 0 {
		ttl = time.Duration(req.SessionTTLSeconds) * time.Second
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if ttl > capTTL {
		return capTTL
	}
	return ttl
}

func parseSessionTTL(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse ttl %q: %w", value, err)
	}
	if ttl <= 0 {
		return 0, fmt.Errorf("ttl must be positive")
	}
	return ttl, nil
}

func durationSeconds(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	return int(ttl.Round(time.Second) / time.Second)
}
