// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type capbrokerServer struct {
	cfg                   *Config
	stateDir              string
	store                 remoteStore
	allowUnsignedDecision bool
	localApprove          bool

	// Permission-upgrade per-agent guards. Lazy-initialized exactly once
	// via upgradeGuardsOnce; safe under concurrent request handlers.
	upgradeGuardsOnce sync.Once
	upgradeRateLimit  *rateLimiter
	upgradeDedup      *reasonDedupCache

	// Serializes permission-upgrade decisions so two operators racing
	// the same pending request can't both write grants. Operators are
	// humans clicking buttons — throughput isn't a concern.
	upgradeDecideMu sync.Mutex
}

// upgradeGuards initializes the rate-limit and dedup primitives once on
// first call and returns them. Thread-safe; concurrent callers see
// the same instances.
func (s *capbrokerServer) upgradeGuards() (*rateLimiter, *reasonDedupCache) {
	s.upgradeGuardsOnce.Do(func() {
		limit := 5
		if s.cfg != nil && s.cfg.PermissionUpgrade.RateLimitPerHour > 0 {
			limit = s.cfg.PermissionUpgrade.RateLimitPerHour
		}
		s.upgradeRateLimit = newRateLimiter(limit, time.Hour)
		s.upgradeDedup = newReasonDedupCache()
	})
	return s.upgradeRateLimit, s.upgradeDedup
}

func runRemoteServer(cfg *Config, stateDir, addr string, allowUnsignedDecision, localApprove bool) error {
	server := capbrokerServer{
		cfg:                   cfg,
		stateDir:              stateDir,
		store:                 newRemoteStore(stateDir),
		allowUnsignedDecision: allowUnsignedDecision,
		localApprove:          localApprove,
	}
	if localApprove {
		// Resume any pending requests left over from a previous daemon run.
		// Without this, requests POSTed just before a daemon restart would
		// hang forever (status=pending, no decider) and the client would
		// time out — even with an active auto-approve lease in place.
		server.resumePendingRequests()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/requests", server.handleRequests)
	mux.HandleFunc("/v1/requests/", server.handleRequestByID)
	mux.HandleFunc("/u/", server.handleUpgradeUI)
	mux.HandleFunc("/v1/upgrades/", server.handleUpgradeAPI)
	return http.ListenAndServe(addr, mux)
}

// resumePendingRequests scans the store for status=pending entries left
// over from a previous run and re-fires the local decider for each.
// Called once at server startup when --local-approve is set.
func (s *capbrokerServer) resumePendingRequests() {
	requests, err := s.store.list()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capbroker: resume scan failed: %v\n", err)
		return
	}
	resumed := 0
	for _, req := range requests {
		if req.Status != remoteStatusPending {
			continue
		}
		resumed++
		go s.localDecideRequest(req)
	}
	if resumed > 0 {
		fmt.Fprintf(os.Stderr, "capbroker: resumed %d pending request(s) after restart\n", resumed)
	}
}

func (s *capbrokerServer) handleRequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createRequest(w, r)
	case http.MethodGet:
		s.listRequests(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *capbrokerServer) createRequest(w http.ResponseWriter, r *http.Request) {
	var create RemoteRequestCreate
	if err := json.NewDecoder(r.Body).Decode(&create); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req := Request{
		Kind:              create.Kind,
		Agent:             create.Agent,
		Profile:           create.Profile,
		Resource:          create.Resource,
		Reason:            create.Reason,
		Command:           create.Command,
		VaultRef:          create.VaultRef,
		VaultField:        create.VaultField,
		TargetProfile:     create.TargetProfile,
		TargetResource:    create.TargetResource,
		GrantMode:         create.GrantMode,
		OriginalRequestID: create.OriginalRequestID,
		SessionTTLSeconds: create.SessionTTLSeconds,
	}
	// `needsCommand` is only meaningful for the command kind. Vault and
	// permission-upgrade requests have empty commands and validateRequest
	// enforces that internally based on profile.Kind.
	needsCommand := req.Kind == "" || req.Kind == requestKindCommand
	// Pass stateDir + now so the validator can extend the allowlist with
	// permanent / non-expired temporal grants persisted by the upgrade flow.
	if _, err := s.cfg.validateRequestAt(req, needsCommand, s.stateDir, time.Now()); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	// Vault requests can ONLY be approved by the local-approve daemon
	// path. The signed-approver flow (approvePendingOnce in
	// remote_approve.go) builds command-style leases via
	// resolveProfileSecrets and never populates SecretValue — a vault
	// request approved that way would round-trip an empty value and
	// look like success to the client. Reject upfront so misconfigured
	// deployments fail loudly instead of returning empty secrets.
	if req.Kind == requestKindVault && !s.localApprove {
		writeError(w, http.StatusForbidden, "vault requests require a local-approve daemon (signed-approver flow does not support authority-side execution)")
		return
	}
	// Cheap input-shape validation BEFORE the rate-limit / dedup spend.
	// A malformed client_public_key would otherwise burn the agent's
	// hourly upgrade quota and lock the dedup key, blocking immediate
	// corrected retries.
	if err := validateLeaseRecipientPublicKey(create.ClientPublicKey); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Permission-upgrade requests have additional anti-spam guards: a
	// per-agent rate limit (default 5/hour) and a reason-dedup window
	// so an agent can't slam the operator with the same justification
	// repeatedly. These run AFTER policy + input-shape validation so a
	// malformed upgrade request returns 403/400 (informative) before
	// the rate-limit counter gets bumped.
	if req.Kind == requestKindPermissionUpgrade {
		if !s.localApprove {
			writeError(w, http.StatusForbidden, "permission-upgrade requests require a local-approve daemon")
			return
		}
		rl, dedup := s.upgradeGuards()
		ok, retry := rl.allow(req.Agent, time.Now())
		if !ok {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retry.Seconds()))
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("permission-upgrade rate limit exceeded for agent %q (retry in %s)", req.Agent, retry.Round(time.Second)))
			return
		}
		dedupKey := req.Agent + "|" + req.TargetProfile + "|" + req.TargetResource + "|" + req.Reason
		if !dedup.markIfFresh(dedupKey, time.Now()) {
			writeError(w, http.StatusBadRequest, "duplicate upgrade request — provide a fresh justification or wait for the previous request to be decided")
			return
		}
	}
	now := time.Now().UTC()
	remoteReq := RemoteRequest{
		ID:                "req_" + randomHex(16),
		Kind:              create.Kind,
		Agent:             create.Agent,
		Profile:           create.Profile,
		Resource:          create.Resource,
		Reason:            create.Reason,
		Command:           create.Command,
		VaultRef:          create.VaultRef,
		VaultField:        create.VaultField,
		TargetProfile:     create.TargetProfile,
		TargetResource:    create.TargetResource,
		GrantMode:         create.GrantMode,
		OriginalRequestID: create.OriginalRequestID,
		SessionTTLSeconds: create.SessionTTLSeconds,
		ClientPublicKey:   create.ClientPublicKey,
		Status:            remoteStatusPending,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	remoteReq, err := s.store.create(remoteReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.localApprove {
		go s.localDecideRequest(remoteReq)
	}
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "remote_request_created",
		Agent:       req.Agent,
		Profile:     req.Profile,
		Resource:    req.Resource,
		Reason:      req.Reason,
		Command:     req.Command,
		RequestHash: requestHash(req),
		GrantID:     remoteReq.ID,
	})
	// Permission-upgrade requests get an additional, more-informative
	// audit event AND a notification dispatch. Both are best-effort
	// (failures don't fail the POST — the operator can still decide
	// via the HTTP form/CLI even if Pushover is down).
	if req.Kind == requestKindPermissionUpgrade {
		_ = appendAudit(s.stateDir, AuditEvent{
			Event:       "permission_upgrade_requested",
			Agent:       req.Agent,
			Profile:     req.Profile,
			Resource:    req.Resource,
			Reason:      req.Reason,
			RequestHash: requestHash(req),
			GrantID:     remoteReq.ID,
			Message: fmt.Sprintf("agent wants %s += %q (mode=%s) — original=%s",
				req.TargetProfile, req.TargetResource, req.GrantMode, req.OriginalRequestID),
		})
		go func(rr RemoteRequest) {
			if err := notifyPermissionUpgrade(s.cfg, rr, s.cfg.PermissionUpgrade.BaseURL, nil); err != nil {
				fmt.Fprintf(os.Stderr, "capbroker: notify permission-upgrade %s: %v\n", rr.ID, err)
			}
		}(remoteReq)
	}
	writeJSON(w, http.StatusCreated, remoteReq)
}

func (s *capbrokerServer) listRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := s.store.list()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	status := r.URL.Query().Get("status")
	if status == "" {
		writeJSON(w, http.StatusOK, requests)
		return
	}
	filtered := requests[:0]
	for _, req := range requests {
		if req.Status == status {
			filtered = append(filtered, req)
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (s *capbrokerServer) handleRequestByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/requests/")
	if rest == "" {
		writeError(w, http.StatusNotFound, "missing request id")
		return
	}
	parts := strings.Split(rest, "/")
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.getRequest(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "decision" && r.Method == http.MethodPost {
		s.decideRequest(w, r, id)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (s *capbrokerServer) getRequest(w http.ResponseWriter, r *http.Request, id string) {
	req, ok, err := s.store.get(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *capbrokerServer) decideRequest(w http.ResponseWriter, r *http.Request, id string) {
	var decision RemoteDecision
	if err := json.NewDecoder(r.Body).Decode(&decision); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if decision.Approved {
		if decision.EncryptedLease == nil {
			writeError(w, http.StatusBadRequest, "approved decision requires encrypted_lease")
			return
		}
		if decision.LeaseExpiresAt == nil {
			writeError(w, http.StatusBadRequest, "approved decision requires lease_expires_at")
			return
		}
	}
	if err := verifyDecisionSignature(s.cfg, id, decision, s.allowUnsignedDecision); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	updated, err := s.store.update(id, func(req *RemoteRequest) error {
		if req.Status != remoteStatusPending {
			return fmt.Errorf("request is already %s", req.Status)
		}
		req.UpdatedAt = time.Now().UTC()
		req.Message = decision.Message
		if decision.Approved {
			req.Status = remoteStatusApproved
			req.EncryptedLease = decision.EncryptedLease
			req.LeaseExpiresAt = decision.LeaseExpiresAt
		} else {
			req.Status = remoteStatusDenied
		}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	approved := decision.Approved
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:       "remote_request_decided",
		Agent:       updated.Agent,
		Profile:     updated.Profile,
		Resource:    updated.Resource,
		Reason:      updated.Reason,
		Command:     updated.Command,
		RequestHash: requestHash(updated.Request()),
		GrantID:     updated.ID,
		Approved:    &approved,
		Message:     decision.Message,
	})
	writeJSON(w, http.StatusOK, updated)
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
