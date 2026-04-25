// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"fmt"
	"net/url"
	"os"
	"time"
)

func runApprove(cfg *Config, server string, keyFile ApproverKeyFile, privateKey ed25519.PrivateKey, watch bool, interval time.Duration) error {
	if server == "" {
		return fmt.Errorf("server is required")
	}
	for {
		if err := approvePendingOnce(cfg, server, keyFile, privateKey); err != nil {
			return err
		}
		if !watch {
			return nil
		}
		time.Sleep(interval)
	}
}

func approvePendingOnce(cfg *Config, server string, keyFile ApproverKeyFile, privateKey ed25519.PrivateKey) error {
	var pending []RemoteRequest
	if err := getJSON(remoteURL(server, "/v1/requests?status="+url.QueryEscape(remoteStatusPending)), &pending); err != nil {
		return err
	}
	for _, remoteReq := range pending {
		req := remoteReq.Request()
		profile, err := cfg.validateRequest(req, true)
		if err != nil {
			if postErr := postDecision(server, remoteReq.ID, signDecision(remoteReq.ID, RemoteDecision{
				Approved: false,
				Approver: keyFile.Name,
				Message:  "local policy denied: " + err.Error(),
			}, privateKey)); postErr != nil {
				return postErr
			}
			continue
		}
		sessionTTL := requestedSessionTTL(cfg, profile, req)
		critical := requestIsCritical(profile, req)
		stateDir := defaultStateDir()
		if !critical {
			grant, err := activeGrant(stateDir, req, time.Now())
			if err != nil {
				return err
			}
			if grant == nil {
				approved, err := promptApproval(req, profile, sessionTTL, critical, time.Duration(cfg.Defaults.ApprovalTimeoutSeconds)*time.Second)
				if err != nil {
					return err
				}
				if !approved {
					decision := signDecision(remoteReq.ID, RemoteDecision{
						Approved: false,
						Approver: keyFile.Name,
						Message:  "denied by local approver",
					}, privateKey)
					if err := postDecision(server, remoteReq.ID, decision); err != nil {
						return err
					}
					continue
				}
				if _, err := createGrant(stateDir, req, sessionTTL, time.Now()); err != nil {
					return err
				}
			}
		} else {
			approved, err := promptApproval(req, profile, sessionTTL, critical, time.Duration(cfg.Defaults.ApprovalTimeoutSeconds)*time.Second)
			if err != nil {
				return err
			}
			if !approved {
				decision := signDecision(remoteReq.ID, RemoteDecision{
					Approved: false,
					Approver: keyFile.Name,
					Message:  "denied by local approver",
				}, privateKey)
				if err := postDecision(server, remoteReq.ID, decision); err != nil {
					return err
				}
				continue
			}
		}
		secrets, err := resolveProfileSecrets(cfg, profile)
		if err != nil {
			decision := signDecision(remoteReq.ID, RemoteDecision{
				Approved: false,
				Approver: keyFile.Name,
				Message:  "secret resolution failed: " + err.Error(),
			}, privateKey)
			if postErr := postDecision(server, remoteReq.ID, decision); postErr != nil {
				return postErr
			}
			continue
		}
		expiresAt := time.Now().Add(time.Duration(profile.TTLSeconds) * time.Second).UTC()
		lease, err := encryptLeaseForRecipient(remoteReq.ClientPublicKey, LeasePayload{
			Env:       secrets.Env,
			Files:     secrets.Files,
			Agent:     remoteReq.Agent,
			Profile:   remoteReq.Profile,
			Resource:  remoteReq.Resource,
			Reason:    remoteReq.Reason,
			Command:   remoteReq.Command,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return err
		}
		decision := signDecision(remoteReq.ID, RemoteDecision{
			Approved:       true,
			Approver:       keyFile.Name,
			Message:        "approved by local approver",
			EncryptedLease: lease,
			LeaseExpiresAt: &expiresAt,
		}, privateKey)
		if err := postDecision(server, remoteReq.ID, decision); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "capbroker: approved remote request %s until %s\n", remoteReq.ID, expiresAt.Format(time.RFC3339))
	}
	return nil
}

func postDecision(server, requestID string, decision RemoteDecision) error {
	var updated RemoteRequest
	return postJSON(remoteURL(server, "/v1/requests/"+url.PathEscape(requestID)+"/decision"), decision, &updated)
}
