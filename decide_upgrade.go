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
	// Serialize the entire decide path so two operators racing the same
	// pending request can't both reach the claim — and even if they do,
	// applyUpgradeApproval claims via atomic store.update before writing
	// the grant (defense-in-depth against the rare case of additional
	// concurrent decision sites).
	s.upgradeDecideMu.Lock()
	defer s.upgradeDecideMu.Unlock()

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

	// Compute grant TTL and lease metadata up-front (no side effects).
	// The grant struct is used both for the eventual write AND for
	// computing the UpgradeGranted marker on the lease.
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
		// no expires_at
	case grantModeOnce:
		grant.ExpiresAt = now.Add(onceTTL)
	case grantModeSession:
		// "session" is bound to the operator's active session TTL. We use
		// the daemon-wide max_session_seconds default — the operator can
		// always revoke earlier by removing the line from temporal-grants.jsonl.
		max := time.Duration(s.cfg.Defaults.MaxSessionSeconds) * time.Second
		if max <= 0 {
			max = 3 * time.Hour
		}
		grant.ExpiresAt = now.Add(max)
	}

	// Build the lease deterministically from the decision (no I/O).
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

	// CLAIM the request first via atomic store.update. If two operators
	// race (or a CLI + HTTP front race), exactly one wins this call;
	// losers see "request is already approved" and never reach the
	// grant write below. Without this ordering, both operators could
	// each append a grant to permanent-grants.jsonl before the second
	// store.update fails, leaving an unintended grant alive.
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

	// We won the race — now persist the grant. If THIS fails (disk full,
	// permissions, etc.) the request is already marked approved with no
	// grant behind it; the agent's retry hits 403, the audit shows
	// permission_upgrade_grant_failed, and the operator can investigate.
	// The inverse failure mode (grant written but request not approved)
	// would silently broaden access — that's the one we never want.
	switch decision.Mode {
	case grantModePermanent:
		if err := appendPermanentGrant(s.stateDir, grant); err != nil {
			s.recordUpgradeGrantFailure(current, decision, err)
			return updated, fmt.Errorf("persist permanent grant: %w", err)
		}
	case grantModeOnce, grantModeSession:
		if err := appendTemporalGrant(s.stateDir, grant); err != nil {
			s.recordUpgradeGrantFailure(current, decision, err)
			return updated, fmt.Errorf("persist %s grant: %w", decision.Mode, err)
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

// recordUpgradeGrantFailure audits the rare case where the request was
// successfully claimed (approved) but the grant write failed downstream.
// The operator can investigate via this audit line; agent retries will
// fail-closed (403) until the grant is hand-applied or the request is
// re-decided.
func (s *capbrokerServer) recordUpgradeGrantFailure(current RemoteRequest, decision upgradeDecision, cause error) {
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "permission_upgrade_grant_failed",
		Agent:       current.Agent,
		Profile:     current.Profile,
		Resource:    current.Resource,
		Reason:      current.Reason,
		RequestHash: requestHash(current.Request()),
		GrantID:     current.ID,
		Message: fmt.Sprintf("approved %s += %q (mode=%s, operator=%s) but grant write failed: %v",
			current.TargetProfile, current.TargetResource, decision.Mode, decision.Operator, cause),
	})
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
