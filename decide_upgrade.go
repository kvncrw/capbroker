// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"
)

// onceTTL is the wall-clock lifetime of a "once" grant. 24h gives an
// agent overnight to retry the original command without re-asking.
const onceTTL = 24 * time.Hour

// upgradeDecision is the operator's decision on a pending permission-upgrade
// request. Mode is one of: grantModeOnce, grantModeSession, grantModePermanent,
// "deny". Operator is a free-form identifier (e.g. "kcrawley@web", "cli")
// recorded in the audit + the grant file for forensic traceability.
type upgradeDecision struct {
	Mode     string
	Operator string
	Message  string // optional — included in audit + denial response to the agent
}

// decidePermissionUpgrade is the shared backend behind both the HTTP review
// form (PR 3) and the `capbroker review-upgrades` CLI (PR 4). Looks up the
// pending request, validates the decision, persists the appropriate grant
// (or marks denied), encrypts a handshake lease, audits, and returns the
// updated RemoteRequest.
//
// Idempotent re-application is intentionally NOT supported: re-deciding an
// already-decided request returns an error. This forces the front door to
// surface the conflict (e.g. "another operator already approved this").
func (s *capbrokerServer) decidePermissionUpgrade(requestID string, decision upgradeDecision) (RemoteRequest, error) {
	current, ok, err := s.store.get(requestID)
	if err != nil {
		return RemoteRequest{}, err
	}
	if !ok {
		return RemoteRequest{}, fmt.Errorf("request %q not found", requestID)
	}
	if current.Kind != requestKindPermissionUpgrade {
		return RemoteRequest{}, fmt.Errorf("request %q is kind %q, not permission-upgrade", requestID, current.Kind)
	}
	if current.Status != remoteStatusPending {
		return RemoteRequest{}, fmt.Errorf("request %q is already %s", requestID, current.Status)
	}

	switch decision.Mode {
	case "deny":
		return s.applyUpgradeDenial(current, decision)
	case grantModeOnce, grantModeSession, grantModePermanent:
		return s.applyUpgradeApproval(current, decision)
	default:
		return RemoteRequest{}, fmt.Errorf("invalid decision mode %q", decision.Mode)
	}
}

func (s *capbrokerServer) applyUpgradeApproval(current RemoteRequest, decision upgradeDecision) (RemoteRequest, error) {
	now := time.Now().UTC()

	// Persist the grant first so a crash between persist and request-update
	// leaves a "granted but request still pending" state — the operator
	// can retry the decision and the grant file's idempotency check (the
	// agent retries, sees the resource is now allowed, succeeds even
	// without the matching upgrade-request approval) will keep things
	// moving. Better than the inverse: an approved request with no grant
	// behind it would silently fail on retry.
	grant := permissionGrant{
		TargetProfile:  current.TargetProfile,
		TargetResource: current.TargetResource,
		GrantMode:      decision.Mode,
		GrantedAt:      now,
		GrantedBy:      decision.Operator,
		RequestID:      current.ID,
		Reason:         current.Reason,
	}
	switch decision.Mode {
	case grantModePermanent:
		if err := appendPermanentGrant(s.stateDir, grant); err != nil {
			return RemoteRequest{}, fmt.Errorf("persist permanent grant: %w", err)
		}
	case grantModeOnce:
		grant.ExpiresAt = now.Add(onceTTL)
		if err := appendTemporalGrant(s.stateDir, grant); err != nil {
			return RemoteRequest{}, fmt.Errorf("persist once grant: %w", err)
		}
	case grantModeSession:
		// "session" is bound to the operator's active session TTL. We use
		// the daemon-wide max_session_seconds default — the operator can
		// always revoke earlier by removing the line from temporal-grants.jsonl.
		max := time.Duration(s.cfg.Defaults.MaxSessionSeconds) * time.Second
		if max <= 0 {
			max = 3 * time.Hour
		}
		grant.ExpiresAt = now.Add(max)
		if err := appendTemporalGrant(s.stateDir, grant); err != nil {
			return RemoteRequest{}, fmt.Errorf("persist session grant: %w", err)
		}
	}
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "permission_upgrade_applied",
		Agent:       current.Agent,
		Profile:     current.Profile,
		Resource:    current.Resource,
		Reason:      current.Reason,
		RequestHash: requestHash(current.Request()),
		GrantID:     current.ID,
		Message: fmt.Sprintf("granted %s += %q (mode=%s, operator=%s)",
			current.TargetProfile, current.TargetResource, decision.Mode, decision.Operator),
	})

	// Build a small lease so the agent client knows the decision and can
	// resume. UpgradeGranted carries the mode + (for temporal) the TTL —
	// the agent uses this to decide whether to retry once or many times.
	upgradeMarker := decision.Mode
	if !grant.ExpiresAt.IsZero() {
		upgradeMarker = fmt.Sprintf("%s:%s", decision.Mode, grant.ExpiresAt.Sub(now).Round(time.Second))
	}
	leaseExpires := now.Add(time.Duration(s.cfg.Defaults.ApprovalTimeoutSeconds) * time.Second)
	if leaseExpires.Before(now.Add(60 * time.Second)) {
		leaseExpires = now.Add(5 * time.Minute) // sane floor
	}
	lease, err := encryptLeaseForRecipient(current.ClientPublicKey, LeasePayload{
		Agent:          current.Agent,
		Profile:        current.Profile,
		Resource:       current.Resource,
		Reason:         current.Reason,
		ExpiresAt:      leaseExpires,
		UpgradeGranted: upgradeMarker,
	})
	if err != nil {
		return RemoteRequest{}, fmt.Errorf("encrypt upgrade lease: %w", err)
	}

	updated, err := s.store.update(current.ID, func(req *RemoteRequest) error {
		if req.Status != remoteStatusPending {
			return fmt.Errorf("request is already %s", req.Status)
		}
		req.Status = remoteStatusApproved
		req.Message = decision.Message
		req.EncryptedLease = lease
		req.LeaseExpiresAt = &leaseExpires
		req.UpdatedAt = now
		return nil
	})
	if err != nil {
		return RemoteRequest{}, fmt.Errorf("mark approved: %w", err)
	}
	approved := true
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "permission_upgrade_decided",
		Agent:       updated.Agent,
		Profile:     updated.Profile,
		Resource:    updated.Resource,
		Reason:      updated.Reason,
		RequestHash: requestHash(updated.Request()),
		GrantID:     updated.ID,
		Approved:    &approved,
		Message:     fmt.Sprintf("mode=%s operator=%s", decision.Mode, decision.Operator),
	})
	return updated, nil
}

func (s *capbrokerServer) applyUpgradeDenial(current RemoteRequest, decision upgradeDecision) (RemoteRequest, error) {
	now := time.Now().UTC()
	updated, err := s.store.update(current.ID, func(req *RemoteRequest) error {
		if req.Status != remoteStatusPending {
			return fmt.Errorf("request is already %s", req.Status)
		}
		req.Status = remoteStatusDenied
		req.Message = decision.Message
		req.UpdatedAt = now
		return nil
	})
	if err != nil {
		return RemoteRequest{}, err
	}
	approved := false
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "permission_upgrade_decided",
		Agent:       updated.Agent,
		Profile:     updated.Profile,
		Resource:    updated.Resource,
		Reason:      updated.Reason,
		RequestHash: requestHash(updated.Request()),
		GrantID:     updated.ID,
		Approved:    &approved,
		Message:     fmt.Sprintf("denied operator=%s msg=%s", decision.Operator, decision.Message),
	})
	return updated, nil
}
