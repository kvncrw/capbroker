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
	Version           int                       `json:"version"`
	Defaults          Defaults                  `json:"defaults"`
	Profiles          map[string]Profile        `json:"profiles"`
	SecretSources     map[string]SecretSource   `json:"secret_sources"`
	SecretProviders   map[string]SecretProvider `json:"secret_providers,omitempty"`
	Remote            RemoteConfig              `json:"remote,omitempty"`
	Notify            NotifyConfig              `json:"notify,omitempty"`
	PermissionUpgrade PermissionUpgradeConfig   `json:"permission_upgrade,omitempty"`
}

// PermissionUpgradeConfig tunes the per-agent guards for permission-upgrade
// requests. Defaults: 5 requests / hour / agent, base URL empty (notify
// won't include approve/diff URLs unless set).
type PermissionUpgradeConfig struct {
	RateLimitPerHour int    `json:"rate_limit_per_hour,omitempty"`
	BaseURL          string `json:"base_url,omitempty"` // e.g. "https://capbroker.crawley.systems"
}

type Defaults struct {
	ApprovalTimeoutSeconds int `json:"approval_timeout_seconds"`
	MaxSessionSeconds      int `json:"max_session_seconds,omitempty"`
}

type Profile struct {
	Description       string            `json:"description"`
	Kind              string            `json:"kind,omitempty"` // "command" (default) | "vault"
	Agents            []string          `json:"agents"`
	Resources         []string          `json:"resources"`
	TTLSeconds        int               `json:"ttl_seconds"`
	MaxSessionSeconds int               `json:"max_session_seconds,omitempty"`
	RequireApproval   bool              `json:"require_approval"`
	AllowedCommands   [][]string        `json:"allowed_commands"`
	CriticalCommands  [][]string        `json:"critical_commands,omitempty"`
	Env               map[string]string `json:"env"`
	Files             map[string]string `json:"files,omitempty"`
	// Vault profile fields. Only consulted when Kind == "vault".
	Vault       string            `json:"vault,omitempty"`        // "bsm" | "bw"
	VaultAuth   string            `json:"vault_auth,omitempty"`   // SecretSource ID resolving the daemon's vault credential
	VaultFields []string          `json:"vault_fields,omitempty"` // bw only: fields the agent may request
	Metadata    map[string]string `json:"metadata"`
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
	// UpgradeApprovers is the allowlist of operator identities (typically
	// email addresses from Cf-Access-Authenticated-User-Email) authorized
	// to decide permission-upgrade requests via the HTTP review surface
	// or the review-upgrades CLI. Fail-closed: if empty AND
	// AllowAnonymousUpgrade is false, all decision attempts are rejected.
	// This is defense-in-depth — the daemon assumes Cloudflare Access (or
	// equivalent) is in front, but enforces the allowlist itself in case
	// CF Access is bypassed (direct tailnet hit, misconfigured ingress,
	// etc.). Without this gate, anyone reachable to the daemon who knew a
	// pending request id could POST /v1/upgrades/{id}/decide and self-grant
	// permanent allowlist entries.
	UpgradeApprovers []string `json:"upgrade_approvers,omitempty"`
	// UpgradeAllowedSources is a CIDR (or bare-IP) allowlist for the
	// SOURCE addresses permitted to POST upgrade decisions. The
	// trusted-identity headers (Cf-Access-...-Email, X-Forwarded-User)
	// can be forged by anyone who can reach the daemon directly, so
	// production daemons exposed beyond loopback should pin this to the
	// CIDR(s) of the proxy/tunnel that injects those headers (e.g. the
	// cloudflared tunnel egress, an internal nginx, a VPN exit). When
	// empty the source check is skipped — fine for laptop-local
	// deployments where the daemon binds to 127.0.0.1 only.
	UpgradeAllowedSources []string `json:"upgrade_allowed_sources,omitempty"`
	// AllowAnonymousUpgrade is the escape hatch: when true, the upgrade
	// decide path accepts decisions with no trusted-header identity and
	// audits them as "anonymous-http". Intended for local dev/test only;
	// production daemons should leave this false and populate
	// UpgradeApprovers.
	AllowAnonymousUpgrade bool `json:"allow_anonymous_upgrade,omitempty"`
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
	if cfg.Defaults.MaxSessionSeconds <= 0 {
		cfg.Defaults.MaxSessionSeconds = 3 * 60 * 60
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
    "approval_timeout_seconds": 120,
    "max_session_seconds": 10800
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
      "critical_commands": [
        ["gh", "repo", "delete"],
        ["git", "push", "--force"]
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
      "critical_commands": [
        ["kubectl", "delete"],
        ["kubectl", "apply"],
        ["kubectl", "patch"]
      ],
      "files": {
        "KUBECONFIG": "kubeconfig_from_provider"
      }
    }
  }
}
`
