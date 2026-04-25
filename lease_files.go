// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func runCommandWithSecrets(command []string, secrets resolvedProfileSecrets) int {
	env, cleanup, redactions, err := prepareCommandEnv(secrets.Env, secrets.Files, secrets.Redactions)
	if err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}
	defer cleanup()
	return runChildCommand(command, env, redactions)
}

func prepareCommandEnv(env map[string]string, files map[string]string, redactions []string) (map[string]string, func(), []string, error) {
	overlay := map[string]string{}
	mergedRedactions := append([]string{}, redactions...)
	for name, value := range env {
		if err := validateEnvName(name); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid env %q: %w", name, err)
		}
		overlay[name] = value
		addRedaction(&mergedRedactions, value)
	}
	if len(files) == 0 {
		return overlay, func() {}, mergedRedactions, nil
	}
	dir, err := os.MkdirTemp("", "capbroker-files-*")
	if err != nil {
		return nil, nil, nil, err
	}
	cleanup := func() {
		_ = os.RemoveAll(dir)
	}
	for envName, content := range files {
		if err := validateEnvName(envName); err != nil {
			cleanup()
			return nil, nil, nil, fmt.Errorf("invalid file env %q: %w", envName, err)
		}
		path := filepath.Join(dir, envName)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			cleanup()
			return nil, nil, nil, err
		}
		overlay[envName] = path
		addRedaction(&mergedRedactions, content)
	}
	return overlay, cleanup, mergedRedactions, nil
}

func validateEnvName(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	for i, r := range name {
		valid := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')
		if !valid {
			return fmt.Errorf("must contain only letters, digits, and underscores, and may not start with a digit")
		}
	}
	return nil
}
