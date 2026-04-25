// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func ensureApproved(cfg *Config, stateDir string, req Request, profile Profile) (Grant, bool, error) {
	now := time.Now()
	if !profile.RequireApproval {
		grant, err := createGrant(stateDir, req, time.Duration(profile.TTLSeconds)*time.Second, now)
		return grant, true, err
	}
	if grant, err := activeGrant(stateDir, req, now); err != nil {
		return Grant{}, false, err
	} else if grant != nil {
		return *grant, false, nil
	}

	approved, err := promptApproval(req, profile, time.Duration(cfg.Defaults.ApprovalTimeoutSeconds)*time.Second)
	if err != nil {
		return Grant{}, false, err
	}
	approvalEvent := approved
	if err := appendAudit(stateDir, AuditEvent{
		Event:       "approval_decision",
		Agent:       req.Agent,
		Profile:     req.Profile,
		Resource:    req.Resource,
		Reason:      req.Reason,
		Command:     req.Command,
		RequestHash: requestHash(req),
		Approved:    &approvalEvent,
	}); err != nil {
		return Grant{}, false, err
	}
	if !approved {
		return Grant{}, false, fmt.Errorf("approval denied")
	}
	grant, err := createGrant(stateDir, req, time.Duration(profile.TTLSeconds)*time.Second, now)
	return grant, true, err
}

func promptApproval(req Request, profile Profile, timeout time.Duration) (bool, error) {
	if os.Getenv("CAPBROKER_AUTO_APPROVE") == "1" {
		return true, nil
	}
	text := approvalText(req, profile)
	if commandExists("zenity") && displayAvailable() {
		args := []string{
			"--question",
			"--title", "Capbroker Approval",
			"--text", text,
			"--width", "560",
		}
		if timeout > 0 {
			args = append(args, "--timeout", fmt.Sprintf("%.0f", timeout.Seconds()))
		}
		return exec.Command("zenity", args...).Run() == nil, nil
	}
	if commandExists("kdialog") && displayAvailable() {
		return exec.Command("kdialog", "--title", "Capbroker Approval", "--yesno", text).Run() == nil, nil
	}
	if commandExists("qarma") && displayAvailable() {
		return exec.Command("qarma", "--question", "--title", "Capbroker Approval", "--text", text).Run() == nil, nil
	}
	if !stdinIsTerminal() {
		return false, fmt.Errorf("no graphical approver available and stdin is not interactive")
	}
	fmt.Fprintf(os.Stderr, "%s\nApprove? [y/N]: ", text)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes", nil
}

func approvalText(req Request, profile Profile) string {
	command := "(none)"
	if len(req.Command) > 0 {
		command = strings.Join(req.Command, " ")
	}
	return fmt.Sprintf(
		"Agent: %s\nProfile: %s\nResource: %s\nTTL: %ds\nReason: %s\nCommand: %s\n\nApprove this local capability grant?",
		req.Agent,
		req.Profile,
		req.Resource,
		profile.TTLSeconds,
		req.Reason,
		command,
	)
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func displayAvailable() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
