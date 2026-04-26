// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"time"
)

const (
	remoteStatusPending  = "pending"
	remoteStatusApproved = "approved"
	remoteStatusDenied   = "denied"
)

// Request kinds. "command" is the original flow (broker injects env/files,
// client exec's a command locally). "vault" runs a vault read on the
// authority and returns just the secret value; the client never sees the
// vault token.
const (
	requestKindCommand = "command"
	requestKindVault   = "vault"
)

type RemoteRequest struct {
	ID                string          `json:"id"`
	Kind              string          `json:"kind,omitempty"`
	Agent             string          `json:"agent"`
	Profile           string          `json:"profile"`
	Resource          string          `json:"resource"`
	Reason            string          `json:"reason"`
	Command           []string        `json:"command"`
	VaultRef          string          `json:"vault_ref,omitempty"`
	VaultField        string          `json:"vault_field,omitempty"`
	SessionTTLSeconds int             `json:"session_ttl_seconds,omitempty"`
	ClientPublicKey   string          `json:"client_public_key"`
	Status            string          `json:"status"`
	Message           string          `json:"message,omitempty"`
	EncryptedLease    *EncryptedLease `json:"encrypted_lease,omitempty"`
	LeaseExpiresAt    *time.Time      `json:"lease_expires_at,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

func (r RemoteRequest) Request() Request {
	return Request{
		Kind:              r.Kind,
		Agent:             r.Agent,
		Profile:           r.Profile,
		Resource:          r.Resource,
		Reason:            r.Reason,
		Command:           r.Command,
		VaultRef:          r.VaultRef,
		VaultField:        r.VaultField,
		SessionTTLSeconds: r.SessionTTLSeconds,
	}
}

type RemoteRequestCreate struct {
	Kind              string   `json:"kind,omitempty"`
	Agent             string   `json:"agent"`
	Profile           string   `json:"profile"`
	Resource          string   `json:"resource"`
	Reason            string   `json:"reason"`
	Command           []string `json:"command"`
	VaultRef          string   `json:"vault_ref,omitempty"`
	VaultField        string   `json:"vault_field,omitempty"`
	SessionTTLSeconds int      `json:"session_ttl_seconds,omitempty"`
	ClientPublicKey   string   `json:"client_public_key"`
}

type RemoteDecision struct {
	Approved       bool            `json:"approved"`
	Approver       string          `json:"approver,omitempty"`
	Message        string          `json:"message,omitempty"`
	EncryptedLease *EncryptedLease `json:"encrypted_lease,omitempty"`
	LeaseExpiresAt *time.Time      `json:"lease_expires_at,omitempty"`
	Signature      string          `json:"signature,omitempty"`
}

type EncryptedLease struct {
	Algorithm       string `json:"algorithm"`
	SenderPublicKey string `json:"sender_public_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

type LeasePayload struct {
	Env         map[string]string `json:"env"`
	Files       map[string]string `json:"files,omitempty"`
	Agent       string            `json:"agent"`
	Profile     string            `json:"profile"`
	Resource    string            `json:"resource"`
	Reason      string            `json:"reason"`
	Command     []string          `json:"command"`
	ExpiresAt   time.Time         `json:"expires_at"`
	SecretValue string            `json:"secret_value,omitempty"` // vault-fetch only
}

func decisionSigningPayload(requestID string, decision RemoteDecision) []byte {
	payload := struct {
		RequestID      string          `json:"request_id"`
		Approved       bool            `json:"approved"`
		Message        string          `json:"message,omitempty"`
		EncryptedLease *EncryptedLease `json:"encrypted_lease,omitempty"`
		LeaseExpiresAt *time.Time      `json:"lease_expires_at,omitempty"`
	}{
		RequestID:      requestID,
		Approved:       decision.Approved,
		Message:        decision.Message,
		EncryptedLease: decision.EncryptedLease,
		LeaseExpiresAt: decision.LeaseExpiresAt,
	}
	data, _ := json.Marshal(payload)
	return data
}
