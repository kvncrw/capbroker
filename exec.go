// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func runScopedCommand(cfg *Config, stateDir string, req Request, profile Profile) int {
	grant, created, err := ensureApproved(cfg, stateDir, req, profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}
	if created {
		fmt.Fprintf(os.Stderr, "capbroker: approved %s until %s\n", grant.ID, grant.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	} else {
		fmt.Fprintf(os.Stderr, "capbroker: using active grant %s until %s\n", grant.ID, grant.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	}

	secrets, err := resolveProfileSecrets(cfg, profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}

	exitCode := runCommandWithSecrets(req.Command, secrets)
	_ = appendAudit(stateDir, AuditEvent{
		Event:       "exec",
		Agent:       req.Agent,
		Profile:     req.Profile,
		Resource:    req.Resource,
		Reason:      req.Reason,
		Command:     req.Command,
		GrantID:     grant.ID,
		RequestHash: requestHash(req),
		ExitCode:    &exitCode,
	})
	return exitCode
}

func runChildCommand(command []string, env map[string]string, redactions []string) int {
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "capbroker: command is required")
		return 2
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = overlayEnv(os.Environ(), env)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 127
	}
	done := make(chan struct{}, 2)
	go streamRedacted(os.Stdout, stdout, redactions, done)
	go streamRedacted(os.Stderr, stderr, redactions, done)
	<-done
	<-done
	err = cmd.Wait()
	return exitCode(err)
}

func streamRedacted(dst io.Writer, src io.Reader, secrets []string, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	scanner := bufio.NewScanner(src)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := redact(scanner.Text(), secrets)
		fmt.Fprintln(dst, line)
	}
}

func redact(s string, secrets []string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, "[REDACTED]")
	}
	return s
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			return status.ExitStatus()
		}
	}
	return 1
}
