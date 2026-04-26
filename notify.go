// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// NotifyConfig describes how the daemon dispatches operator notifications
// (today, just permission-upgrade requests). Capbroker stays decoupled from
// any specific provider — the operator wires up Pushover/Discord/email/etc.
// by setting the command and listing which SecretSources to inject as env.
type NotifyConfig struct {
	PermissionUpgrade *NotifyTarget `json:"permission_upgrade,omitempty"`
}

// NotifyTarget configures a single notifier action. Type=="command" runs
// `command` with the request body JSON on stdin and the resolved
// SecretSources injected as env vars (key = env var name, value = source ID).
// Type=="" (or absent) disables the notifier — failures are logged but
// never block the upgrade flow.
type NotifyTarget struct {
	Type           string            `json:"type"` // "command" today; "http" reserved
	Command        []string          `json:"command,omitempty"`
	SecretSources  map[string]string `json:"secret_sources,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

// notificationBody is the JSON shape piped to the notifier's stdin. Includes
// the agent's reason, the target diff, and pre-rendered approve / diff URLs
// so the notifier just substitutes into a Pushover / Discord / email
// template without re-deriving anything.
type notificationBody struct {
	ID                string   `json:"id"`
	Agent             string   `json:"agent"`
	Profile           string   `json:"profile"`
	TargetProfile     string   `json:"target_profile"`
	TargetResource    string   `json:"target_resource"`
	GrantMode         string   `json:"grant_mode"`
	Reason            string   `json:"reason"`
	OriginalRequestID string   `json:"original_request_id,omitempty"`
	OriginalCommand   []string `json:"original_command,omitempty"`
	ApproveURL        string   `json:"approve_url,omitempty"`
	DiffURL           string   `json:"diff_url,omitempty"`
}

// notifyExecutor lets tests intercept the subprocess. Production uses
// defaultNotifyExec which actually shells out.
type notifyExecutor func(ctx context.Context, command []string, env []string, stdin []byte) error

var defaultNotifyExec notifyExecutor = func(ctx context.Context, command []string, env []string, stdin []byte) error {
	if len(command) == 0 {
		return fmt.Errorf("empty notify command")
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = append([]string{}, env...) // clean env — same hardening as vault.go
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("notify command exited: %s", msg)
	}
	return nil
}

// notifyPermissionUpgrade fires the configured notifier for a freshly-
// created permission-upgrade request. Failures are returned for the caller
// to log; the caller MUST NOT block the request flow on a notification
// failure (a flaky Pushover should never prevent the operator from being
// able to decide via the HTTP form or CLI).
func notifyPermissionUpgrade(cfg *Config, req RemoteRequest, baseURL string, exec notifyExecutor) error {
	if cfg == nil || cfg.Notify.PermissionUpgrade == nil {
		return nil // not configured = silent (operator opted out)
	}
	target := cfg.Notify.PermissionUpgrade
	if target.Type != "command" {
		return fmt.Errorf("notify target type %q unsupported (want 'command')", target.Type)
	}
	if exec == nil {
		exec = defaultNotifyExec
	}

	// Resolve any secret sources the notifier wants in env. Failures
	// here ARE returned because they indicate misconfig the operator
	// should see (a Pushover token that won't resolve will produce
	// silent dropped notifications otherwise).
	env := make([]string, 0, len(target.SecretSources)+1)
	env = append(env, "PATH=/usr/local/bin:/usr/bin:/bin")
	for envVar, sourceID := range target.SecretSources {
		source, ok := cfg.SecretSources[sourceID]
		if !ok {
			return fmt.Errorf("notify references unknown secret source %q", sourceID)
		}
		val, err := resolveSecretSource(cfg, source)
		if err != nil {
			return fmt.Errorf("resolve notify secret %q: %w", sourceID, err)
		}
		env = append(env, envVar+"="+val)
	}

	body := notificationBody{
		ID:                req.ID,
		Agent:             req.Agent,
		Profile:           req.Profile,
		TargetProfile:     req.TargetProfile,
		TargetResource:    req.TargetResource,
		GrantMode:         req.GrantMode,
		Reason:            req.Reason,
		OriginalRequestID: req.OriginalRequestID,
	}
	if baseURL != "" {
		body.ApproveURL = strings.TrimRight(baseURL, "/") + "/u/" + req.ID
		body.DiffURL = body.ApproveURL + "/diff"
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	timeout := time.Duration(target.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec(ctx, target.Command, env, data)
}
