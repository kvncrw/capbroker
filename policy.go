// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

type Request struct {
	Kind              string   `json:"kind,omitempty"`
	Agent             string   `json:"agent"`
	Profile           string   `json:"profile"`
	Resource          string   `json:"resource"`
	Reason            string   `json:"reason"`
	Command           []string `json:"command,omitempty"`
	VaultRef          string   `json:"vault_ref,omitempty"`
	VaultField        string   `json:"vault_field,omitempty"`
	TargetProfile     string   `json:"target_profile,omitempty"`
	TargetResource    string   `json:"target_resource,omitempty"`
	GrantMode         string   `json:"grant_mode,omitempty"`
	OriginalRequestID string   `json:"original_request_id,omitempty"`
	SessionTTLSeconds int      `json:"session_ttl_seconds,omitempty"`
}

func (c *Config) validateRequest(req Request, needsCommand bool) (Profile, error) {
	return c.validateRequestAt(req, needsCommand, "", time.Now())
}

// validateRequestAt is the same as validateRequest but with the stateDir
// + clock injected so the resource allowlist can be extended by
// permanent + non-expired temporal grants. Pass stateDir == "" to skip
// the dynamic extension (useful for the bare CLI `request` flow that
// has no daemon state context).
func (c *Config) validateRequestAt(req Request, needsCommand bool, stateDir string, now time.Time) (Profile, error) {
	profile, ok := c.Profiles[req.Profile]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q", req.Profile)
	}
	// Normalize kind on both request and profile so empty == "command".
	reqKind := req.Kind
	if reqKind == "" {
		reqKind = requestKindCommand
	}
	profKind := profile.Kind
	if profKind == "" {
		profKind = requestKindCommand
	}
	if reqKind != profKind {
		return Profile{}, fmt.Errorf("request kind %q does not match profile %q kind %q", reqKind, req.Profile, profKind)
	}
	if !matchesAny(profile.Agents, req.Agent) {
		return Profile{}, fmt.Errorf("agent %q is not allowed for profile %q", req.Agent, req.Profile)
	}
	// Resource check — extended by permanent + temporal grants when stateDir
	// is set. permission-upgrade kind is intentionally NOT extended this
	// way: an upgrade asks to extend a target profile, but the meta-profile
	// itself must be statically operator-managed (see plan §self-extension).
	allowed := profile.Resources
	if stateDir != "" && profKind != requestKindPermissionUpgrade {
		allowed = effectiveResources(stateDir, req.Profile, profile.Resources, now)
	}
	if !matchesAny(allowed, req.Resource) {
		return Profile{}, fmt.Errorf("resource %q is not allowed for profile %q", req.Resource, req.Profile)
	}
	switch profKind {
	case requestKindVault:
		if err := validateVaultRequest(profile, req); err != nil {
			return Profile{}, err
		}
	case requestKindPermissionUpgrade:
		if err := validatePermissionUpgradeRequest(c, profile, req); err != nil {
			return Profile{}, err
		}
	case requestKindCommand:
		if needsCommand {
			if len(req.Command) == 0 {
				return Profile{}, fmt.Errorf("command is required")
			}
			if !commandAllowed(profile.AllowedCommands, req.Command) {
				return Profile{}, fmt.Errorf("command %q is not allowed by profile %q", req.Command[0], req.Profile)
			}
		}
	default:
		return Profile{}, fmt.Errorf("profile %q has unknown kind %q", req.Profile, profKind)
	}
	if profile.TTLSeconds <= 0 {
		profile.TTLSeconds = 300
	}
	return profile, nil
}

func validateVaultRequest(profile Profile, req Request) error {
	if profile.Vault == "" {
		return fmt.Errorf("vault profile %q has no 'vault' provider configured", req.Profile)
	}
	if profile.Vault != "bsm" && profile.Vault != "bw" {
		return fmt.Errorf("vault profile %q has unsupported vault %q (want bsm|bw)", req.Profile, profile.Vault)
	}
	if req.VaultRef == "" {
		return fmt.Errorf("vault request requires vault_ref")
	}
	// Resource is the vault ref — it was already allowlisted above. Enforce
	// that resource and vault_ref match exactly so a leaked resource match
	// can't be used to fetch a different ref.
	if req.Resource != req.VaultRef {
		return fmt.Errorf("vault request resource %q must equal vault_ref %q", req.Resource, req.VaultRef)
	}
	// Command must be empty for vault requests — defends against a client
	// trying to smuggle a command through a vault-typed profile.
	if len(req.Command) > 0 {
		return fmt.Errorf("vault request must not include a command")
	}
	if profile.Vault == "bw" {
		if req.VaultField == "" {
			return fmt.Errorf("bw vault request requires vault_field")
		}
		if !stringInList(profile.VaultFields, req.VaultField) {
			return fmt.Errorf("vault_field %q is not allowed by profile %q", req.VaultField, req.Profile)
		}
	}
	return nil
}

func stringInList(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

func matchesAny(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if pattern == "*" || pattern == value {
			return true
		}
		if ok, _ := path.Match(pattern, value); ok {
			return true
		}
	}
	return false
}

func commandAllowed(prefixes [][]string, command []string) bool {
	if len(prefixes) == 0 {
		return false
	}
	for _, prefix := range prefixes {
		if len(prefix) == 0 || len(command) < len(prefix) {
			continue
		}
		ok := true
		for i := range prefix {
			if command[i] != prefix[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func commandCritical(prefixes [][]string, command []string) bool {
	return commandAllowed(prefixes, command)
}

func requestIsCritical(profile Profile, req Request) bool {
	return len(req.Command) > 0 && commandCritical(profile.CriticalCommands, req.Command)
}

// validatePermissionUpgradeRequest enforces the rules a permission-upgrade
// request must follow. The meta-profile has already been agent-checked
// and resource-checked (Resource == TargetProfile, on the meta-profile's
// resources allowlist) by the caller; this function checks the rest:
// the target profile must exist, must NOT be a permission-upgrade kind
// itself (no self-extension), the grant mode must be valid, the target
// resource must be a non-empty literal (no globs), the reason must be
// substantive, and command must be empty (defense against smuggling
// a command through a vault- or upgrade-typed profile).
func validatePermissionUpgradeRequest(c *Config, profile Profile, req Request) error {
	if req.TargetProfile == "" {
		return fmt.Errorf("permission-upgrade request requires target_profile")
	}
	if req.Resource != req.TargetProfile {
		return fmt.Errorf("permission-upgrade resource %q must equal target_profile %q", req.Resource, req.TargetProfile)
	}
	target, ok := c.Profiles[req.TargetProfile]
	if !ok {
		return fmt.Errorf("target profile %q does not exist", req.TargetProfile)
	}
	// No self-extension. The meta-profile resources list is the only place
	// permission-upgrade extensibility lives — don't let an agent expand it
	// at runtime.
	if target.Kind == requestKindPermissionUpgrade {
		return fmt.Errorf("cannot upgrade permissions of a permission-upgrade profile (%q)", req.TargetProfile)
	}
	switch req.GrantMode {
	case grantModeOnce, grantModeSession, grantModePermanent:
	case "":
		return fmt.Errorf("permission-upgrade request requires grant_mode (once|session|permanent)")
	default:
		return fmt.Errorf("permission-upgrade grant_mode %q invalid (want once|session|permanent)", req.GrantMode)
	}
	if req.TargetResource == "" {
		return fmt.Errorf("permission-upgrade request requires target_resource")
	}
	// Reject any glob/wildcard metacharacter — only literal extensions.
	// path.Match meta chars: * ? [
	if strings.ContainsAny(req.TargetResource, "*?[") {
		return fmt.Errorf("target_resource %q must be a literal value (no glob characters)", req.TargetResource)
	}
	// Reason must be substantive — too-short reasons are typically agent
	// laziness and the operator can't make a good decision without context.
	if utf8.RuneCountInString(strings.TrimSpace(req.Reason)) < 30 {
		return fmt.Errorf("permission-upgrade reason must be ≥30 characters of substantive justification")
	}
	if len(req.Command) > 0 {
		return fmt.Errorf("permission-upgrade request must not include a command")
	}
	return nil
}
