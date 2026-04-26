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
	sessionTTL := requestedSessionTTL(cfg, profile, req)
	critical := requestIsCritical(profile, req)
	if !profile.RequireApproval {
		grant, err := createGrant(stateDir, req, sessionTTL, now)
		return grant, true, err
	}
	if !critical {
		if grant, err := activeGrant(stateDir, req, now); err != nil {
			return Grant{}, false, err
		} else if grant != nil {
			return *grant, false, nil
		}
	}

	// Auto-approve lease (file-based, time-bounded — see auto_approve.go).
	// Checked before any prompt so an operator who's away from the keyboard
	// can pre-authorize a short window of approvals. Hard-capped at
	// MaxAutoApproveTTL (currently 30m) so a forgotten lease can't last all day.
	if lease, active := readAutoApproveLease(stateDir, now); active {
		approvedTrue := true
		_ = appendAudit(stateDir, AuditEvent{
			Event:       "auto_approve_lease_used",
			Agent:       req.Agent,
			Profile:     req.Profile,
			Resource:    req.Resource,
			Reason:      req.Reason,
			Command:     req.Command,
			RequestHash: requestHash(req),
			Approved:    &approvedTrue,
			Message: fmt.Sprintf("auto-approve lease active until %s; lease reason=%q",
				lease.ExpiresAt.Format(time.RFC3339), lease.Reason),
		})
		if critical {
			return ephemeralGrant(req, sessionTTL, now, "auto_approve_critical"), true, nil
		}
		grant, err := createGrant(stateDir, req, sessionTTL, now)
		return grant, true, err
	}

	approved, err := promptApproval(req, profile, sessionTTL, critical, time.Duration(cfg.Defaults.ApprovalTimeoutSeconds)*time.Second)
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
	if critical {
		return ephemeralGrant(req, sessionTTL, now, "critical_approval"), true, nil
	}
	grant, err := createGrant(stateDir, req, sessionTTL, now)
	return grant, true, err
}

func promptApproval(req Request, profile Profile, sessionTTL time.Duration, critical bool, timeout time.Duration) (bool, error) {
	if os.Getenv("CAPBROKER_AUTO_APPROVE") == "1" {
		return true, nil
	}
	text := approvalText(req, profile, sessionTTL, critical)
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

func approvalText(req Request, profile Profile, sessionTTL time.Duration, critical bool) string {
	command := "(none)"
	if len(req.Command) > 0 {
		command = strings.Join(req.Command, " ")
	}
	scope := "operator session"
	if critical {
		scope = "critical one-command approval"
	}
	return fmt.Sprintf(
		"Agent: %s\nProfile: %s\nResource: %s\nApproval: %s\nSession TTL: %s\nReason: %s\nCommand: %s\n\nApprove this capability?",
		req.Agent,
		req.Profile,
		req.Resource,
		scope,
		sessionTTL.Round(time.Second),
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
