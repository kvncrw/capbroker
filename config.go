// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const configVersion = 1

type Config struct {
	Version         int                       `json:"version"`
	Defaults        Defaults                  `json:"defaults"`
	Profiles        map[string]Profile        `json:"profiles"`
	SecretSources   map[string]SecretSource   `json:"secret_sources"`
	SecretProviders map[string]SecretProvider `json:"secret_providers,omitempty"`
	Remote          RemoteConfig              `json:"remote,omitempty"`
}

type Defaults struct {
	ApprovalTimeoutSeconds int `json:"approval_timeout_seconds"`
}

type Profile struct {
	Description     string            `json:"description"`
	Agents          []string          `json:"agents"`
	Resources       []string          `json:"resources"`
	TTLSeconds      int               `json:"ttl_seconds"`
	RequireApproval bool              `json:"require_approval"`
	AllowedCommands [][]string        `json:"allowed_commands"`
	Env             map[string]string `json:"env"`
	Files           map[string]string `json:"files,omitempty"`
	Metadata        map[string]string `json:"metadata"`
}

type SecretSource struct {
	Type     string            `json:"type"`
	Env      string            `json:"env,omitempty"`
	File     string            `json:"file,omitempty"`
	Command  []string          `json:"command,omitempty"`
	Provider string            `json:"provider,omitempty"`
	Ref      string            `json:"ref,omitempty"`
	Field    string            `json:"field,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Trim     *bool             `json:"trim,omitempty"`
	Hint     string            `json:"hint,omitempty"`
}

type SecretProvider struct {
	Type    string   `json:"type"`
	Command []string `json:"command,omitempty"`
}

type RemoteConfig struct {
	Approvers map[string]string `json:"approvers,omitempty"`
}

func loadConfig(path string) (*Config, error) {
	if path == "" {
		path = defaultConfigPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.Version != configVersion {
		return nil, fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]Profile{}
	}
	if cfg.SecretSources == nil {
		cfg.SecretSources = map[string]SecretSource{}
	}
	if cfg.SecretProviders == nil {
		cfg.SecretProviders = map[string]SecretProvider{}
	}
	if cfg.Defaults.ApprovalTimeoutSeconds <= 0 {
		cfg.Defaults.ApprovalTimeoutSeconds = 120
	}
	return &cfg, nil
}

func writeDefaultConfig(path string) error {
	if path == "" {
		path = defaultConfigPath()
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(defaultConfigJSON), 0o600)
}

func defaultConfigPath() string {
	if v := os.Getenv("CAPBROKER_CONFIG"); v != "" {
		return v
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(homeDir(), ".config")
	}
	return filepath.Join(base, "capbroker", "config.json")
}

func defaultStateDir() string {
	if v := os.Getenv("CAPBROKER_STATE_DIR"); v != "" {
		return v
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		base = filepath.Join(homeDir(), ".local", "state")
	}
	return filepath.Join(base, "capbroker")
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "."
}

const defaultConfigJSON = `{
  "version": 1,
  "defaults": {
    "approval_timeout_seconds": 120
  },
  "secret_sources": {
    "github_token_from_gh_cli": {
      "type": "command",
      "command": ["gh", "auth", "token"],
      "hint": "Run gh auth login -h github.com, or change this source to a password manager/GitHub App token command."
    },
    "kubeconfig_from_provider": {
      "type": "provider",
      "provider": "example-vault",
      "ref": "kubernetes/read-only-kubeconfig",
      "field": "value",
      "hint": "Replace example-vault with a real provider command such as Bitwarden Secrets Manager, 1Password, Vault, or AWS Secrets Manager."
    }
  },
  "secret_providers": {
    "example-vault": {
      "type": "command",
      "command": ["capbroker-provider-example"]
    }
  },
  "profiles": {
    "github-review": {
      "description": "Allow an agent to run GitHub review/read commands with a short-lived local approval.",
      "agents": ["remote-agent", "codex", "claude", "opencode"],
      "resources": ["example-org/*"],
      "ttl_seconds": 900,
      "require_approval": true,
      "allowed_commands": [
        ["gh", "pr", "view"],
        ["gh", "pr", "diff"],
        ["gh", "pr", "review"],
        ["git", "fetch"],
        ["git", "clone"],
        ["git", "push"]
      ],
      "env": {
        "GH_TOKEN": "github_token_from_gh_cli"
      }
    },
    "k8s-read": {
      "description": "Read-only kubectl access after local approval. Use Kubernetes RBAC for the real permission boundary.",
      "agents": ["remote-agent", "codex", "claude", "opencode"],
      "resources": ["namespace/*"],
      "ttl_seconds": 600,
      "require_approval": true,
      "allowed_commands": [
        ["kubectl", "get"],
        ["kubectl", "describe"],
        ["kubectl", "logs"]
      ],
      "files": {
        "KUBECONFIG": "kubeconfig_from_provider"
      }
    }
  }
}
`
