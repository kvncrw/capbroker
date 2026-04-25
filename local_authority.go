// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"
)

func (s *capbrokerServer) localDecideRequest(remoteReq RemoteRequest) {
	req := remoteReq.Request()
	profile, err := s.cfg.validateRequest(req, true)
	if err != nil {
		s.localDeny(remoteReq.ID, "local policy denied: "+err.Error())
		return
	}
	approved, err := promptApproval(req, profile, time.Duration(s.cfg.Defaults.ApprovalTimeoutSeconds)*time.Second)
	if err != nil {
		s.localDeny(remoteReq.ID, "local approval failed: "+err.Error())
		return
	}
	if !approved {
		s.localDeny(remoteReq.ID, "denied by local approver")
		return
	}
	secrets, err := resolveProfileSecrets(s.cfg, profile)
	if err != nil {
		s.localDeny(remoteReq.ID, "secret resolution failed: "+err.Error())
		return
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
		s.localDeny(remoteReq.ID, "lease encryption failed: "+err.Error())
		return
	}
	updated, err := s.store.update(remoteReq.ID, func(req *RemoteRequest) error {
		if req.Status != remoteStatusPending {
			return fmt.Errorf("request is already %s", req.Status)
		}
		req.Status = remoteStatusApproved
		req.Message = "approved by local authority"
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
		Message:     "approved by local authority",
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
