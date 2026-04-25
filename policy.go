// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"path"
)

type Request struct {
	Agent             string   `json:"agent"`
	Profile           string   `json:"profile"`
	Resource          string   `json:"resource"`
	Reason            string   `json:"reason"`
	Command           []string `json:"command,omitempty"`
	SessionTTLSeconds int      `json:"session_ttl_seconds,omitempty"`
}

func (c *Config) validateRequest(req Request, needsCommand bool) (Profile, error) {
	profile, ok := c.Profiles[req.Profile]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q", req.Profile)
	}
	if !matchesAny(profile.Agents, req.Agent) {
		return Profile{}, fmt.Errorf("agent %q is not allowed for profile %q", req.Agent, req.Profile)
	}
	if !matchesAny(profile.Resources, req.Resource) {
		return Profile{}, fmt.Errorf("resource %q is not allowed for profile %q", req.Resource, req.Profile)
	}
	if needsCommand {
		if len(req.Command) == 0 {
			return Profile{}, fmt.Errorf("command is required")
		}
		if !commandAllowed(profile.AllowedCommands, req.Command) {
			return Profile{}, fmt.Errorf("command %q is not allowed by profile %q", req.Command[0], req.Profile)
		}
	}
	if profile.TTLSeconds <= 0 {
		profile.TTLSeconds = 300
	}
	return profile, nil
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
