// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"net/url"
	"os"
	"time"
)

func runRemoteCommand(server string, req Request, waitTimeout, pollInterval time.Duration) int {
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
		Agent:             req.Agent,
		Profile:           req.Profile,
		Resource:          req.Resource,
		Reason:            req.Reason,
		Command:           req.Command,
		SessionTTLSeconds: req.SessionTTLSeconds,
		ClientPublicKey:   publicKey,
	}, &created); err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "capbroker: remote request %s pending\n", created.ID)
	deadline := time.Now().Add(waitTimeout)
	for {
		var current RemoteRequest
		if err := getJSON(remoteURL(server, "/v1/requests/"+url.PathEscape(created.ID)), &current); err != nil {
			fmt.Fprintln(os.Stderr, "capbroker:", err)
			return 1
		}
		switch current.Status {
		case remoteStatusApproved:
			if current.EncryptedLease == nil {
				fmt.Fprintln(os.Stderr, "capbroker: approved request has no encrypted lease")
				return 1
			}
			payload, err := decryptLease(privateKey, *current.EncryptedLease)
			if err != nil {
				fmt.Fprintln(os.Stderr, "capbroker:", err)
				return 1
			}
			if time.Now().After(payload.ExpiresAt) {
				fmt.Fprintln(os.Stderr, "capbroker: remote lease expired before use")
				return 1
			}
			if !sameCommand(payload.Command, req.Command) || payload.Agent != req.Agent || payload.Profile != req.Profile || payload.Resource != req.Resource {
				fmt.Fprintln(os.Stderr, "capbroker: remote lease does not match requested capability")
				return 1
			}
			fmt.Fprintf(os.Stderr, "capbroker: remote request %s approved until %s\n", current.ID, payload.ExpiresAt.Format(time.RFC3339))
			return runCommandWithLease(req, payload)
		case remoteStatusDenied:
			if current.Message != "" {
				fmt.Fprintf(os.Stderr, "capbroker: remote request denied: %s\n", current.Message)
			} else {
				fmt.Fprintln(os.Stderr, "capbroker: remote request denied")
			}
			return 1
		case remoteStatusPending:
			if time.Now().After(deadline) {
				fmt.Fprintln(os.Stderr, "capbroker: timed out waiting for remote approval")
				return 1
			}
			time.Sleep(pollInterval)
		default:
			fmt.Fprintf(os.Stderr, "capbroker: remote request has unknown status %q\n", current.Status)
			return 1
		}
	}
}

func runCommandWithEnv(req Request, env map[string]string) int {
	return runCommandWithLease(req, LeasePayload{Env: env})
}

func runCommandWithLease(req Request, payload LeasePayload) int {
	redactions := make([]string, 0, len(payload.Env)+len(payload.Files))
	for _, value := range payload.Env {
		if len(value) >= 4 {
			redactions = append(redactions, value)
		}
	}
	for _, value := range payload.Files {
		if len(value) >= 4 {
			redactions = append(redactions, value)
		}
	}
	return runCommandWithSecrets(req.Command, resolvedProfileSecrets{
		Env:        payload.Env,
		Files:      payload.Files,
		Redactions: redactions,
	})
}

func sameCommand(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// runVaultFetch posts a vault-kind request, waits for approval, decrypts
// the lease, and writes ONLY the secret value to stdout (no newline —
// callers can pipe directly into a config file or env var). Status output
// goes to stderr so a normal `cap-bsm-get UUID > out.txt` works as
// expected.
//
// Mirrors runRemoteCommand's polling loop closely; intentionally not
// extracted to a shared helper because the success-action differs and
// the loop is simple enough to read inline.
func runVaultFetch(server string, req Request, waitTimeout, pollInterval time.Duration) int {
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
		Kind:              requestKindVault,
		Agent:             req.Agent,
		Profile:           req.Profile,
		Resource:          req.Resource,
		Reason:            req.Reason,
		VaultRef:          req.VaultRef,
		VaultField:        req.VaultField,
		SessionTTLSeconds: req.SessionTTLSeconds,
		ClientPublicKey:   publicKey,
	}, &created); err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "capbroker: vault request %s pending\n", created.ID)
	deadline := time.Now().Add(waitTimeout)
	for {
		var current RemoteRequest
		if err := getJSON(remoteURL(server, "/v1/requests/"+url.PathEscape(created.ID)), &current); err != nil {
			fmt.Fprintln(os.Stderr, "capbroker:", err)
			return 1
		}
		switch current.Status {
		case remoteStatusApproved:
			if current.EncryptedLease == nil {
				fmt.Fprintln(os.Stderr, "capbroker: approved request has no encrypted lease")
				return 1
			}
			payload, err := decryptLease(privateKey, *current.EncryptedLease)
			if err != nil {
				fmt.Fprintln(os.Stderr, "capbroker:", err)
				return 1
			}
			if time.Now().After(payload.ExpiresAt) {
				fmt.Fprintln(os.Stderr, "capbroker: remote lease expired before use")
				return 1
			}
			// Lease must match the capability we asked for, narrow form for vault.
			if payload.Agent != req.Agent || payload.Profile != req.Profile || payload.Resource != req.Resource {
				fmt.Fprintln(os.Stderr, "capbroker: remote lease does not match requested capability")
				return 1
			}
			// An empty SecretValue is a legitimate outcome — vault items can
			// hold empty strings (uninitialized password field, intentionally
			// blank notes, etc.). We treat the approved-decision-with-empty-
			// payload case as a successful fetch and let the caller decide
			// how to handle it; the daemon's authority-side execution path
			// is what enforces "this ref actually exists" upstream.
			fmt.Fprintf(os.Stderr, "capbroker: vault request %s approved until %s\n", current.ID, payload.ExpiresAt.Format(time.RFC3339))
			// stdout is the secret. No trailing newline — caller decides.
			if _, err := os.Stdout.Write([]byte(payload.SecretValue)); err != nil {
				fmt.Fprintln(os.Stderr, "capbroker:", err)
				return 1
			}
			return 0
		case remoteStatusDenied:
			if current.Message != "" {
				fmt.Fprintf(os.Stderr, "capbroker: remote request denied: %s\n", current.Message)
			} else {
				fmt.Fprintln(os.Stderr, "capbroker: remote request denied")
			}
			return 1
		case remoteStatusPending:
			if time.Now().After(deadline) {
				fmt.Fprintln(os.Stderr, "capbroker: timed out waiting for remote approval")
				return 1
			}
			time.Sleep(pollInterval)
		default:
			fmt.Fprintf(os.Stderr, "capbroker: remote request has unknown status %q\n", current.Status)
			return 1
		}
	}
}
