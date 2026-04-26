// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// vaultOutputCap caps the bytes captured from a vault subprocess. Defends
// against pathological vault items (multi-MB notes, etc.) being shipped
// through the broker. The cap covers stdout AND stderr combined.
const vaultOutputCap = 1 << 20 // 1 MiB

// vaultExecTimeout is the wall-clock budget for a single vault read.
const vaultExecTimeout = 30 * time.Second

// vaultExecutor runs the underlying vault binary (`bws` or `bw`). Production
// uses execCommand; tests inject a mock. The contract: given the binary
// name + args + env, return stdout (capped) or an error including the
// captured stderr for diagnostics.
type vaultExecutor func(ctx context.Context, bin string, args []string, env []string) (stdout []byte, err error)

// vaultDefaultExec is the production executor. It's a package-level var so
// the integration test in remote_server_test.go can swap it for the
// resolveVaultRef call path that runs inside localDecideRequest's
// goroutine (where we can't pass an executor argument through the HTTP
// handler chain).
var vaultDefaultExec vaultExecutor = defaultVaultExecutor

// defaultVaultExecutor runs the binary with a clean env (only the vars the
// caller passed) so the vault token cannot leak in via the daemon's
// process env. Output is capped to vaultOutputCap; the executor FAILS
// CLOSED when either stream exceeds the cap — silently truncating
// could ship a corrupted credential to the client.
func defaultVaultExecutor(ctx context.Context, bin string, args []string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append([]string{}, env...) // clean env; do NOT leak ambient vars
	var stdout, stderr bytes.Buffer
	stdoutCap := &cappedWriter{w: &stdout, cap: vaultOutputCap}
	stderrCap := &cappedWriter{w: &stderr, cap: vaultOutputCap}
	cmd.Stdout = stdoutCap
	cmd.Stderr = stderrCap
	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return nil, fmt.Errorf("%s exited %v: %s", bin, err, errMsg)
	}
	if stdoutCap.exceeded {
		return nil, fmt.Errorf("%s output exceeded %d-byte cap", bin, vaultOutputCap)
	}
	return stdout.Bytes(), nil
}

// cappedWriter discards any write past `cap` bytes and reports an error
// the first time the cap is exceeded (so the executor surfaces it).
type cappedWriter struct {
	w        io.Writer
	cap      int
	written  int
	exceeded bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.written >= c.cap {
		c.exceeded = true
		return len(p), nil
	}
	remaining := c.cap - c.written
	if len(p) > remaining {
		_, err := c.w.Write(p[:remaining])
		c.written = c.cap
		c.exceeded = true
		if err != nil {
			return remaining, err
		}
		return len(p), nil
	}
	n, err := c.w.Write(p)
	c.written += n
	return n, err
}

// resolveVaultRef executes the appropriate vault read on the authority
// host and returns just the secret VALUE. The vault token (BWS_ACCESS_TOKEN
// or BW_SESSION) is resolved from the daemon's SecretSources and injected
// into the subprocess env only — never returned to the requester.
//
// Errors are intentionally vague to avoid leaking config details across
// the wire; they're sanitized further at the audit/lease layer.
func resolveVaultRef(cfg *Config, profile Profile, req Request, exec vaultExecutor) (string, error) {
	if exec == nil {
		exec = vaultDefaultExec
	}
	if profile.VaultAuth == "" {
		return "", fmt.Errorf("vault profile %q missing vault_auth secret source", req.Profile)
	}
	source, ok := cfg.SecretSources[profile.VaultAuth]
	if !ok {
		return "", fmt.Errorf("vault profile %q references unknown secret source %q", req.Profile, profile.VaultAuth)
	}
	token, err := resolveSecretSource(cfg, source)
	if err != nil {
		return "", fmt.Errorf("resolve vault auth %q: %w", profile.VaultAuth, err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		// Fail closed. For bw this happens when the local vault is
		// locked (~/.local/state/bw-v/session is empty); for bsm it
		// would mean the cluster bws-token Secret has an empty value.
		return "", fmt.Errorf("vault %q authority credential is empty (vault locked or token missing)", profile.Vault)
	}

	ctx, cancel := context.WithTimeout(context.Background(), vaultExecTimeout)
	defer cancel()

	switch profile.Vault {
	case "bsm":
		return runBsmGet(ctx, exec, token, req.VaultRef)
	case "bw":
		return runBwGet(ctx, exec, token, req.VaultField, req.VaultRef)
	default:
		return "", fmt.Errorf("unsupported vault %q", profile.Vault)
	}
}

// runBsmGet runs `bws secret get <UUID> --output json` and extracts the
// "value" field from the JSON response.
func runBsmGet(ctx context.Context, exec vaultExecutor, token, ref string) (string, error) {
	out, err := exec(ctx, "bws", []string{"secret", "get", ref, "--output", "json"},
		[]string{"BWS_ACCESS_TOKEN=" + token, "PATH=/usr/local/bin:/usr/bin:/bin"})
	if err != nil {
		return "", err
	}
	if len(out) == 0 {
		return "", errors.New("bws returned empty output")
	}
	var parsed struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return "", fmt.Errorf("parse bws output: %w", err)
	}
	return parsed.Value, nil
}

// runBwGet runs `bw get <field> <ref> --session <token>` and returns
// stdout verbatim (trimmed). The bw CLI prints the requested field
// directly when --session is provided.
func runBwGet(ctx context.Context, exec vaultExecutor, session, field, ref string) (string, error) {
	if field == "" {
		return "", errors.New("bw vault read requires vault_field")
	}
	args := []string{"get", field, ref, "--session", session, "--raw"}
	out, err := exec(ctx, "bw", args, []string{"PATH=/usr/local/bin:/usr/bin:/bin"})
	if err != nil {
		return "", err
	}
	value := strings.TrimRight(string(out), "\n")
	if value == "" {
		return "", fmt.Errorf("bw returned empty value for ref %q field %q", ref, field)
	}
	return value, nil
}
