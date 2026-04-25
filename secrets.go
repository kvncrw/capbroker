// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type resolvedProfileSecrets struct {
	Env        map[string]string
	Files      map[string]string
	Redactions []string
}

func resolveProfileEnv(cfg *Config, profile Profile) (map[string]string, []string, error) {
	secrets, err := resolveProfileSecrets(cfg, profile)
	if err != nil {
		return nil, nil, err
	}
	return secrets.Env, secrets.Redactions, nil
}

func resolveProfileSecrets(cfg *Config, profile Profile) (resolvedProfileSecrets, error) {
	resolved := resolvedProfileSecrets{
		Env:   map[string]string{},
		Files: map[string]string{},
	}
	for envName, sourceID := range profile.Env {
		source, ok := cfg.SecretSources[sourceID]
		if !ok {
			return resolvedProfileSecrets{}, fmt.Errorf("unknown secret source %q for env %s", sourceID, envName)
		}
		value, err := resolveSecretSource(cfg, source)
		if err != nil {
			return resolvedProfileSecrets{}, fmt.Errorf("resolve %q: %w%s", sourceID, err, secretSourceHintSuffix(source))
		}
		resolved.Env[envName] = value
		addRedaction(&resolved.Redactions, value)
	}
	for envName, sourceID := range profile.Files {
		if err := validateEnvName(envName); err != nil {
			return resolvedProfileSecrets{}, fmt.Errorf("invalid file env %q: %w", envName, err)
		}
		source, ok := cfg.SecretSources[sourceID]
		if !ok {
			return resolvedProfileSecrets{}, fmt.Errorf("unknown secret source %q for file env %s", sourceID, envName)
		}
		value, err := resolveSecretSource(cfg, source)
		if err != nil {
			return resolvedProfileSecrets{}, fmt.Errorf("resolve %q: %w%s", sourceID, err, secretSourceHintSuffix(source))
		}
		resolved.Files[envName] = value
		addRedaction(&resolved.Redactions, value)
	}
	return resolved, nil
}

func resolveSecretSource(cfg *Config, source SecretSource) (string, error) {
	trim := true
	if source.Trim != nil {
		trim = *source.Trim
	}
	var value string
	switch source.Type {
	case "env":
		if source.Env == "" {
			return "", fmt.Errorf("env source missing env")
		}
		var ok bool
		value, ok = os.LookupEnv(source.Env)
		if !ok {
			return "", fmt.Errorf("environment variable %s is unset", source.Env)
		}
	case "file":
		if source.File == "" {
			return "", fmt.Errorf("file source missing file")
		}
		data, err := os.ReadFile(expandHome(source.File))
		if err != nil {
			return "", err
		}
		value = string(data)
	case "command":
		if len(source.Command) == 0 {
			return "", fmt.Errorf("command source missing command")
		}
		data, err := runSecretCommand(source.Command, nil)
		if err != nil {
			return "", err
		}
		value = string(data)
	case "provider":
		data, err := resolveProviderSource(cfg, source)
		if err != nil {
			return "", err
		}
		value = string(data)
	default:
		return "", fmt.Errorf("unsupported secret source type %q", source.Type)
	}
	if trim {
		value = strings.TrimSpace(value)
	}
	if value == "" {
		return "", fmt.Errorf("secret source returned empty value")
	}
	return value, nil
}

func resolveProviderSource(cfg *Config, source SecretSource) ([]byte, error) {
	if source.Provider == "" {
		return nil, fmt.Errorf("provider source missing provider")
	}
	provider, ok := cfg.SecretProviders[source.Provider]
	if !ok {
		return nil, fmt.Errorf("unknown secret provider %q", source.Provider)
	}
	if provider.Type == "" {
		provider.Type = "command"
	}
	if provider.Type != "command" {
		return nil, fmt.Errorf("unsupported secret provider type %q", provider.Type)
	}
	if len(provider.Command) == 0 {
		return nil, fmt.Errorf("secret provider %q missing command", source.Provider)
	}
	req := providerRequest{
		Ref:      source.Ref,
		Field:    source.Field,
		Metadata: source.Metadata,
	}
	stdin, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	stdin = append(stdin, '\n')
	return runSecretCommand(provider.Command, stdin)
}

type providerRequest struct {
	Ref      string            `json:"ref,omitempty"`
	Field    string            `json:"field,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func runSecretCommand(command []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(command[0], command[1:]...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v failed: %w: %s", command, err, strings.TrimSpace(stderr.String()))
	}
	return data, nil
}

func addRedaction(redactions *[]string, value string) {
	if len(value) >= 4 {
		*redactions = append(*redactions, value)
	}
}

func secretSourceHintSuffix(source SecretSource) string {
	if source.Hint == "" {
		return ""
	}
	return "; hint: " + source.Hint
}

func expandHome(path string) string {
	if path == "~" {
		return homeDir()
	}
	if strings.HasPrefix(path, "~/") {
		return homeDir() + path[1:]
	}
	return path
}

func overlayEnv(base []string, extra map[string]string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(base)+len(extra))
	for _, entry := range base {
		name := entry
		if idx := strings.IndexByte(entry, '='); idx >= 0 {
			name = entry[:idx]
		}
		if _, exists := extra[name]; exists {
			continue
		}
		seen[name] = true
		out = append(out, entry)
	}
	for name, value := range extra {
		if seen[name] {
			continue
		}
		out = append(out, name+"="+value)
	}
	return out
}
