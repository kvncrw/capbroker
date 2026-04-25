// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestRemoteServerSignedDecisionFlow(t *testing.T) {
	t.Parallel()
	keyPath := t.TempDir() + "/approver.key"
	keyFile, err := writeApproverKey("local-authority", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := readApproverKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Profiles: map[string]Profile{
			"github-review": {
				Agents:          []string{"remote-agent"},
				Resources:       []string{"example-org/*"},
				TTLSeconds:      60,
				RequireApproval: true,
				AllowedCommands: [][]string{{"gh", "pr", "view"}},
			},
		},
		Remote: RemoteConfig{Approvers: map[string]string{"local-authority": keyFile.PublicKey}},
	}
	server := capbrokerServer{
		cfg:      cfg,
		stateDir: t.TempDir(),
		store:    newRemoteStore(t.TempDir()),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/requests", server.handleRequests)
	mux.HandleFunc("/v1/requests/", server.handleRequestByID)

	clientPrivateKey, clientPublicKey, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	var created RemoteRequest
	err = performJSON(mux, http.MethodPost, "/v1/requests", RemoteRequestCreate{
		Agent:           "remote-agent",
		Profile:         "github-review",
		Resource:        "example-org/example-repo",
		Reason:          "review",
		Command:         []string{"gh", "pr", "view", "142"},
		ClientPublicKey: clientPublicKey,
	}, &created)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Minute).UTC()
	lease, err := encryptLeaseForRecipient(created.ClientPublicKey, LeasePayload{
		Env:       map[string]string{"GH_TOKEN": "secret-token"},
		Agent:     created.Agent,
		Profile:   created.Profile,
		Resource:  created.Resource,
		Reason:    created.Reason,
		Command:   created.Command,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	decision := signDecision(created.ID, RemoteDecision{
		Approved:       true,
		Approver:       "local-authority",
		EncryptedLease: lease,
		LeaseExpiresAt: &expiresAt,
	}, privateKey)
	var updated RemoteRequest
	err = performJSON(mux, http.MethodPost, "/v1/requests/"+url.PathEscape(created.ID)+"/decision", decision, &updated)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != remoteStatusApproved {
		t.Fatalf("expected approved request, got %s", updated.Status)
	}
	payload, err := decryptLease(clientPrivateKey, *updated.EncryptedLease)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Env["GH_TOKEN"] != "secret-token" {
		t.Fatalf("unexpected token %q", payload.Env["GH_TOKEN"])
	}
}

func performJSON(handler http.Handler, method, path string, request, response interface{}) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return decodeRemoteResponse(rec.Result(), response)
}
