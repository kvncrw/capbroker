// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"
)

func (s *capbrokerServer) localDecideRequest(remoteReq RemoteRequest) {
	req := remoteReq.Request()
	// `needsCommand` is meaningful only for command kind. Vault + upgrade
	// profiles have empty Command and validateRequest enforces that.
	needsCommand := req.Kind == "" || req.Kind == requestKindCommand
	// Use validateRequestAt so dynamically-granted permissions count
	// (permanent + non-expired temporal grants from the upgrade flow).
	profile, err := s.cfg.validateRequestAt(req, needsCommand, s.stateDir, time.Now())
	if err != nil {
		s.localDeny(remoteReq.ID, "local policy denied: "+err.Error())
		return
	}
	sessionTTL := requestedSessionTTL(s.cfg, profile, req)
	critical := requestIsCritical(profile, req)
	if !critical {
		grant, err := activeGrant(s.stateDir, req, time.Now())
		if err != nil {
			s.localDeny(remoteReq.ID, "operator session lookup failed: "+err.Error())
			return
		}
		if grant != nil {
			s.localApproveRequest(remoteReq, profile, "approved by active operator session "+grant.ID)
			return
		}
	}
	approved, err := promptApproval(req, profile, sessionTTL, critical, time.Duration(s.cfg.Defaults.ApprovalTimeoutSeconds)*time.Second)
	if err != nil {
		s.localDeny(remoteReq.ID, "local approval failed: "+err.Error())
		return
	}
	if !approved {
		s.localDeny(remoteReq.ID, "denied by local approver")
		return
	}
	if !critical {
		if _, err := createGrant(s.stateDir, req, sessionTTL, time.Now()); err != nil {
			s.localDeny(remoteReq.ID, "operator session creation failed: "+err.Error())
			return
		}
	}
	s.localApproveRequest(remoteReq, profile, "approved by local authority")
}

func (s *capbrokerServer) localApproveRequest(remoteReq RemoteRequest, profile Profile, message string) {
	expiresAt := time.Now().Add(time.Duration(profile.TTLSeconds) * time.Second).UTC()

	payload := LeasePayload{
		Agent:     remoteReq.Agent,
		Profile:   remoteReq.Profile,
		Resource:  remoteReq.Resource,
		Reason:    remoteReq.Reason,
		Command:   remoteReq.Command,
		ExpiresAt: expiresAt,
	}

	kind := remoteReq.Kind
	if kind == "" {
		kind = requestKindCommand
	}

	switch kind {
	case requestKindVault:
		// Authority-side execution: run bws/bw on this host, capture
		// just the secret value, ship it inside the encrypted lease.
		// The vault token never crosses the wire to the client.
		value, err := resolveVaultRef(s.cfg, profile, remoteReq.Request(), nil)
		if err != nil {
			s.recordVaultFailure(remoteReq, err.Error())
			s.localDeny(remoteReq.ID, "vault lookup failed: "+err.Error())
			return
		}
		payload.SecretValue = value
	case requestKindCommand:
		secrets, err := resolveProfileSecrets(s.cfg, profile)
		if err != nil {
			s.localDeny(remoteReq.ID, "secret resolution failed: "+err.Error())
			return
		}
		payload.Env = secrets.Env
		payload.Files = secrets.Files
	default:
		s.localDeny(remoteReq.ID, "unsupported request kind: "+kind)
		return
	}

	lease, err := encryptLeaseForRecipient(remoteReq.ClientPublicKey, payload)
	if err != nil {
		s.localDeny(remoteReq.ID, "lease encryption failed: "+err.Error())
		return
	}
	updated, err := s.store.update(remoteReq.ID, func(req *RemoteRequest) error {
		if req.Status != remoteStatusPending {
			return fmt.Errorf("request is already %s", req.Status)
		}
		req.Status = remoteStatusApproved
		req.Message = message
		req.EncryptedLease = lease
		req.LeaseExpiresAt = &expiresAt
		req.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		fmt.Printf("capbroker: local approve failed for %s: %v\n", remoteReq.ID, err)
		return
	}
	approvedEvent := true
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "remote_request_decided",
		Agent:       updated.Agent,
		Profile:     updated.Profile,
		Resource:    updated.Resource,
		Reason:      updated.Reason,
		Command:     updated.Command,
		RequestHash: requestHash(updated.Request()),
		GrantID:     updated.ID,
		Approved:    &approvedEvent,
		Message:     message,
	})
	if kind == requestKindVault {
		_ = appendAudit(s.stateDir, AuditEvent{
			Event:       "vault_value_returned",
			Agent:       updated.Agent,
			Profile:     updated.Profile,
			Resource:    updated.Resource,
			Reason:      updated.Reason,
			RequestHash: requestHash(updated.Request()),
			GrantID:     updated.ID,
			Message:     fmt.Sprintf("vault=%s ref=%s field=%s", profile.Vault, remoteReq.VaultRef, remoteReq.VaultField),
		})
	}
}

func (s *capbrokerServer) recordVaultFailure(remoteReq RemoteRequest, reason string) {
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "vault_lookup_failed",
		Agent:       remoteReq.Agent,
		Profile:     remoteReq.Profile,
		Resource:    remoteReq.Resource,
		Reason:      remoteReq.Reason,
		RequestHash: requestHash(remoteReq.Request()),
		GrantID:     remoteReq.ID,
		Message:     reason,
	})
}

func (s *capbrokerServer) localDeny(requestID, message string) {
	updated, err := s.store.update(requestID, func(req *RemoteRequest) error {
		if req.Status != remoteStatusPending {
			return fmt.Errorf("request is already %s", req.Status)
		}
		req.Status = remoteStatusDenied
		req.Message = message
		req.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		fmt.Printf("capbroker: local deny failed for %s: %v\n", requestID, err)
		return
	}
	approvedEvent := false
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "remote_request_decided",
		Agent:       updated.Agent,
		Profile:     updated.Profile,
		Resource:    updated.Resource,
		Reason:      updated.Reason,
		Command:     updated.Command,
		RequestHash: requestHash(updated.Request()),
		GrantID:     updated.ID,
		Approved:    &approvedEvent,
		Message:     message,
	})
}
