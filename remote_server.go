// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type capbrokerServer struct {
	cfg                   *Config
	stateDir              string
	store                 remoteStore
	allowUnsignedDecision bool
	localApprove          bool
}

func runRemoteServer(cfg *Config, stateDir, addr string, allowUnsignedDecision, localApprove bool) error {
	server := capbrokerServer{
		cfg:                   cfg,
		stateDir:              stateDir,
		store:                 newRemoteStore(stateDir),
		allowUnsignedDecision: allowUnsignedDecision,
		localApprove:          localApprove,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/requests", server.handleRequests)
	mux.HandleFunc("/v1/requests/", server.handleRequestByID)
	return http.ListenAndServe(addr, mux)
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
		Agent:             create.Agent,
		Profile:           create.Profile,
		Resource:          create.Resource,
		Reason:            create.Reason,
		Command:           create.Command,
		SessionTTLSeconds: create.SessionTTLSeconds,
	}
	if _, err := s.cfg.validateRequest(req, true); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := validateLeaseRecipientPublicKey(create.ClientPublicKey); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	remoteReq := RemoteRequest{
		ID:                "req_" + randomHex(16),
		Agent:             create.Agent,
		Profile:           create.Profile,
		Resource:          create.Resource,
		Reason:            create.Reason,
		Command:           create.Command,
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
