// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// cmdRequestUpgrade is the agent-side CLI: post a permission-upgrade request,
// wait for the operator's decision, exit 0 (granted) or 1 (denied/timeout).
// The lease the daemon returns carries an UpgradeGranted marker but no
// secret; the agent's job after exit-0 is just to retry the original
// command — which will now succeed because the grant is in temporal- or
// permanent-grants.jsonl and effectiveResources() picks it up.
func cmdRequestUpgrade(args []string) {
	fs := flag.NewFlagSet("request-upgrade", flag.ExitOnError)
	server := fs.String("server", "", "capbrokerd server URL (or CAPBROKER_SERVER)")
	agent := fs.String("agent", "unknown", "agent name")
	profileName := fs.String("profile", "permission-upgrade", "meta-profile (defaults to permission-upgrade)")
	target := fs.String("target-profile", "", "profile to extend (e.g. k8s-read)")
	resource := fs.String("target-resource", "", "literal resource value to add (no globs)")
	mode := fs.String("grant-mode", "once", "once | session | permanent")
	reason := fs.String("reason", "", "justification (≥30 chars; surfaced to operator + audit)")
	original := fs.String("original-request", "", "request id that hit the original 403 (optional)")
	wait := fs.Duration("wait", 5*time.Minute, "approval wait timeout")
	interval := fs.Duration("interval", 2*time.Second, "approval poll interval")
	_ = fs.Parse(args)

	if *target == "" || *resource == "" {
		die(fmt.Errorf("request-upgrade requires --target-profile and --target-resource"))
	}
	if *reason == "" {
		die(fmt.Errorf("request-upgrade requires --reason (≥30 chars)"))
	}
	req := Request{
		Kind:              requestKindPermissionUpgrade,
		Agent:             *agent,
		Profile:           *profileName,
		Resource:          *target, // server enforces Resource == TargetProfile
		Reason:            *reason,
		TargetProfile:     *target,
		TargetResource:    *resource,
		GrantMode:         *mode,
		OriginalRequestID: *original,
	}
	os.Exit(runRequestUpgrade(*server, req, *wait, *interval))
}

// runRequestUpgrade polls until decision lands. Mirrors runVaultFetch's
// loop but with no payload extraction — success just means "the grant is
// live, agent can retry the original command".
func runRequestUpgrade(server string, req Request, waitTimeout, pollInterval time.Duration) int {
	if server == "" {
		server = os.Getenv("CAPBROKER_SERVER")
		if server == "" {
			fmt.Fprintln(os.Stderr, "capbroker: server is required")
			return 2
		}
	}
	privateKey, publicKey, err := generateLeaseRecipientKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}
	var created RemoteRequest
	if err := postJSON(remoteURL(server, "/v1/requests"), RemoteRequestCreate{
		Kind:              requestKindPermissionUpgrade,
		Agent:             req.Agent,
		Profile:           req.Profile,
		Resource:          req.Resource,
		Reason:            req.Reason,
		TargetProfile:     req.TargetProfile,
		TargetResource:    req.TargetResource,
		GrantMode:         req.GrantMode,
		OriginalRequestID: req.OriginalRequestID,
		ClientPublicKey:   publicKey,
	}, &created); err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "capbroker: upgrade request %s pending — operator notified\n", created.ID)
	deadline := time.Now().Add(waitTimeout)
	for {
		var current RemoteRequest
		if err := getJSON(remoteURL(server, "/v1/requests/"+url.PathEscape(created.ID)), &current); err != nil {
			fmt.Fprintln(os.Stderr, "capbroker:", err)
			return 1
		}
		switch current.Status {
		case remoteStatusApproved:
			// Fail closed if the handshake lease isn't there or doesn't
			// decrypt — same posture as remote-run/vault-fetch. An
			// approved-without-lease state could be a tampered store, a
			// crash mid-write, or a server bug; treating it as "go ahead"
			// would have the agent retry against an allowlist that may
			// not actually have the grant, producing a confusing 403 loop.
			if current.EncryptedLease == nil {
				fmt.Fprintln(os.Stderr, "capbroker: approved upgrade has no encrypted lease — refusing to claim grant")
				return 1
			}
			payload, err := decryptLease(privateKey, *current.EncryptedLease)
			if err != nil {
				fmt.Fprintf(os.Stderr, "capbroker: upgrade lease decrypt failed: %v\n", err)
				return 1
			}
			if payload.UpgradeGranted == "" {
				fmt.Fprintln(os.Stderr, "capbroker: upgrade lease missing UpgradeGranted marker — refusing to claim grant")
				return 1
			}
			// Lease must bind to the request we asked about. Without this
			// check, a stale or replayed lease for a different agent /
			// profile / resource would be accepted as a grant for OUR
			// retry. Mirrors the same defense in runRemoteCommand /
			// runVaultFetch.
			if payload.Agent != req.Agent || payload.Profile != req.Profile || payload.Resource != req.Resource {
				fmt.Fprintf(os.Stderr,
					"capbroker: upgrade lease does not bind to this request (agent=%s profile=%s resource=%s vs lease agent=%s profile=%s resource=%s)\n",
					req.Agent, req.Profile, req.Resource,
					payload.Agent, payload.Profile, payload.Resource,
				)
				return 1
			}
			marker := "granted: " + payload.UpgradeGranted
			fmt.Fprintf(os.Stderr, "capbroker: upgrade %s — retry the original command\n", marker)
			fmt.Println(marker)
			return 0
		case remoteStatusDenied:
			if current.Message != "" {
				fmt.Fprintf(os.Stderr, "capbroker: upgrade denied: %s\n", current.Message)
			} else {
				fmt.Fprintln(os.Stderr, "capbroker: upgrade denied")
			}
			return 1
		case remoteStatusPending:
			if time.Now().After(deadline) {
				fmt.Fprintln(os.Stderr, "capbroker: timed out waiting for upgrade decision")
				return 1
			}
			time.Sleep(pollInterval)
		default:
			fmt.Fprintf(os.Stderr, "capbroker: upgrade request has unknown status %q\n", current.Status)
			return 1
		}
	}
}

// cmdReviewUpgrades is the operator-side interactive CLI: list pending
// permission-upgrade requests from a remote daemon and decide each one
// in turn. Same backend (decidePermissionUpgrade via /v1/upgrades/{id}/decide)
// as the HTTP form, so behavior is identical regardless of front door.
func cmdReviewUpgrades(args []string) {
	fs := flag.NewFlagSet("review-upgrades", flag.ExitOnError)
	server := fs.String("server", "", "capbrokerd server URL (or CAPBROKER_SERVER)")
	watch := fs.Bool("watch", false, "loop indefinitely, polling for new pending upgrades")
	pollEvery := fs.Duration("interval", 5*time.Second, "watch poll interval")
	operator := fs.String("operator", "", "operator identity for audit (default: $USER@cli)")
	_ = fs.Parse(args)

	if *server == "" {
		*server = os.Getenv("CAPBROKER_SERVER")
		if *server == "" {
			die(fmt.Errorf("review-upgrades requires --server or CAPBROKER_SERVER"))
		}
	}
	op := *operator
	if op == "" {
		op = os.Getenv("USER") + "@cli"
	}
	in := bufio.NewReader(os.Stdin)
	for {
		pending, err := fetchPendingUpgrades(*server)
		if err != nil {
			die(err)
		}
		if len(pending) == 0 {
			if !*watch {
				fmt.Println("no pending permission-upgrade requests")
				return
			}
			time.Sleep(*pollEvery)
			continue
		}
		for i, req := range pending {
			renderPendingUpgrade(i+1, len(pending), req)
			choice, ok := promptUpgradeChoice(in)
			if !ok {
				return
			}
			switch choice {
			case "n":
				continue
			case "":
				continue
			}
			mode := upgradeChoiceToMode(choice, req.GrantMode)
			if mode == "" {
				fmt.Fprintf(os.Stderr, "unknown choice %q — skipping\n", choice)
				continue
			}
			updated, err := postUpgradeDecision(*server, req.ID, mode, "", op)
			if err != nil {
				fmt.Fprintf(os.Stderr, "decide failed: %v\n", err)
				continue
			}
			fmt.Printf("→ %s: %s\n\n", updated.ID, updated.Status)
		}
		if !*watch {
			return
		}
	}
}

// renderPendingUpgrade prints the operator-visible summary card for a
// single pending request. Kept parallel-ish to the HTML form's layout
// so the operator sees the same info regardless of front door.
func renderPendingUpgrade(idx, total int, req RemoteRequest) {
	fmt.Printf("[%d/%d] %s wants %s += %s\n", idx, total, req.Agent, req.TargetProfile, req.TargetResource)
	fmt.Printf("       requested mode: %s\n", req.GrantMode)
	fmt.Printf("       reason: %q\n", req.Reason)
	if req.OriginalRequestID != "" {
		fmt.Printf("       original request: %s\n", req.OriginalRequestID)
	}
	fmt.Printf("       request id: %s (created %s)\n", req.ID, req.CreatedAt.Format(time.RFC3339))
}

// promptUpgradeChoice reads one keystroke-style line from the operator.
// EOF/empty-with-EOF returns ok=false so the caller can quit cleanly.
// Keys mirror the HTML buttons + 'n' (skip) and 'q' (quit).
func promptUpgradeChoice(in *bufio.Reader) (string, bool) {
	fmt.Print("[a]llow as proposed | [o]nce | [s]ession | [p]ermanent | [d]eny | [n]ext | [q]uit > ")
	line, err := in.ReadString('\n')
	if err != nil {
		return "", false
	}
	choice := strings.ToLower(strings.TrimSpace(line))
	if choice == "q" {
		return "", false
	}
	return choice, true
}

// upgradeChoiceToMode maps an operator keystroke to a decide-mode string.
// "a" defers to the mode the agent originally requested. Empty return
// means "unrecognized — let the caller skip".
func upgradeChoiceToMode(choice, requested string) string {
	switch choice {
	case "a", "allow":
		return requested
	case "o", "once":
		return grantModeOnce
	case "s", "session":
		return grantModeSession
	case "p", "permanent":
		return grantModePermanent
	case "d", "deny":
		return "deny"
	}
	return ""
}

func fetchPendingUpgrades(server string) ([]RemoteRequest, error) {
	var all []RemoteRequest
	if err := getJSON(remoteURL(server, "/v1/requests"), &all); err != nil {
		return nil, fmt.Errorf("list requests: %w", err)
	}
	pending := make([]RemoteRequest, 0, len(all))
	for _, r := range all {
		if r.Kind == requestKindPermissionUpgrade && r.Status == remoteStatusPending {
			pending = append(pending, r)
		}
	}
	return pending, nil
}

func postUpgradeDecision(server, id, mode, message, operator string) (RemoteRequest, error) {
	var updated RemoteRequest
	body := struct {
		Mode    string `json:"mode"`
		Message string `json:"message,omitempty"`
	}{Mode: mode, Message: message}
	// Operator identity flows via the same trusted-header path the HTTP
	// form uses; over loopback/Tailscale the daemon will see this
	// header and audit the decision under it. Behind Cloudflare Access
	// (which would replace this header), the CLI path is intended for
	// laptop-local use so the gating applied is the daemon's own
	// authentication (currently Tailnet ACLs).
	url := remoteURL(server, "/v1/upgrades/"+url.PathEscape(id)+"/decide")
	err := postJSONWithHeader(url, body, &updated, "Cf-Access-Authenticated-User-Email", operator)
	return updated, err
}
