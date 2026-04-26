// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"path"
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
	SessionTTLSeconds int      `json:"session_ttl_seconds,omitempty"`
}

func (c *Config) validateRequest(req Request, needsCommand bool) (Profile, error) {
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
	if !matchesAny(profile.Resources, req.Resource) {
		return Profile{}, fmt.Errorf("resource %q is not allowed for profile %q", req.Resource, req.Profile)
	}
	switch profKind {
	case requestKindVault:
		if err := validateVaultRequest(profile, req); err != nil {
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
