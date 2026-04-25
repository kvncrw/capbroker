// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"sort"
)

func runDoctor(cfg *Config, profileName string) bool {
	ok := true
	fmt.Printf("config: version %d\n", cfg.Version)

	if profileName != "" {
		profile, exists := cfg.Profiles[profileName]
		if !exists {
			fmt.Printf("profile %s: fail: unknown profile\n", profileName)
			return false
		}
		return doctorProfile(cfg, profileName, profile)
	}

	names := sortedProfileNames(cfg.Profiles)
	if len(names) == 0 {
		fmt.Println("profiles: fail: none configured")
		return false
	}
	for _, name := range names {
		if !doctorProfile(cfg, name, cfg.Profiles[name]) {
			ok = false
		}
	}
	return ok
}

func doctorProfile(cfg *Config, name string, profile Profile) bool {
	ok := true
	fmt.Printf("profile %s:\n", name)
	if len(profile.Env) == 0 && len(profile.Files) == 0 {
		fmt.Println("  secrets: none")
		return true
	}
	for _, envName := range sortedEnvNames(profile.Env) {
		sourceID := profile.Env[envName]
		source, exists := cfg.SecretSources[sourceID]
		if !exists {
			fmt.Printf("  env %s <- %s: fail: unknown secret source\n", envName, sourceID)
			ok = false
			continue
		}
		if _, err := resolveSecretSource(cfg, source); err != nil {
			fmt.Printf("  env %s <- %s: fail: %v%s\n", envName, sourceID, err, secretSourceHintSuffix(source))
			ok = false
			continue
		}
		fmt.Printf("  env %s <- %s: ok\n", envName, sourceID)
	}
	for _, envName := range sortedEnvNames(profile.Files) {
		sourceID := profile.Files[envName]
		source, exists := cfg.SecretSources[sourceID]
		if !exists {
			fmt.Printf("  file %s <- %s: fail: unknown secret source\n", envName, sourceID)
			ok = false
			continue
		}
		if err := validateEnvName(envName); err != nil {
			fmt.Printf("  file %s <- %s: fail: invalid env name: %v\n", envName, sourceID, err)
			ok = false
			continue
		}
		if _, err := resolveSecretSource(cfg, source); err != nil {
			fmt.Printf("  file %s <- %s: fail: %v%s\n", envName, sourceID, err, secretSourceHintSuffix(source))
			ok = false
			continue
		}
		fmt.Printf("  file %s <- %s: ok\n", envName, sourceID)
	}
	return ok
}

func sortedProfileNames(profiles map[string]Profile) []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedEnvNames(env map[string]string) []string {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
