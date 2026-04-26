// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestRemoteServerVaultFetchFlow(t *testing.T) {
	// Cannot t.Parallel() — uses t.Setenv to skip the interactive prompt.
	// Local-approve daemon flow: client posts a vault request, the
	// localDecideRequest goroutine resolves the secret on the authority
	// (mocked here via a file-typed SecretSource standing in for the
	// vault subprocess), encrypts the value, returns it inside the lease.
	dir := t.TempDir()
	tokenFile := dir + "/bws.token"
	if err := writeFileForTest(tokenFile, "fake-bws-access-token"); err != nil {
		t.Fatal(err)
	}
	trim := true
	cfg := &Config{
		SecretSources: map[string]SecretSource{
			"bws_access_token": {Type: "file", File: tokenFile, Trim: &trim},
		},
		Profiles: map[string]Profile{
			"bsm-fetch": {
				Kind:       requestKindVault,
				Vault:      "bsm",
				VaultAuth:  "bws_access_token",
				Agents:     []string{"hermes"},
				Resources:  []string{"5da84bec-9b21-4e7f-a720-b41b00cad9d5"},
				TTLSeconds: 60,
			},
		},
	}
	server := capbrokerServer{
		cfg:          cfg,
		stateDir:     t.TempDir(),
		store:        newRemoteStore(t.TempDir()),
		localApprove: true,
	}
	// Skip the interactive prompt — promptApproval() short-circuits when
	// CAPBROKER_AUTO_APPROVE=1. Cleaner than wiring a TTY mock.
	t.Setenv("CAPBROKER_AUTO_APPROVE", "1")
	// Replace the global executor for this test only. The default would
	// shell out to a real bws binary; we want to assert the wiring.
	oldExec := vaultDefaultExec
	vaultDefaultExec = func(ctx context.Context, bin string, args []string, env []string) ([]byte, error) {
		if bin != "bws" {
			t.Errorf("expected bws, got %s", bin)
		}
		if !envContains(env, "BWS_ACCESS_TOKEN=fake-bws-access-token") {
			t.Errorf("BWS_ACCESS_TOKEN not propagated: %v", env)
		}
		return []byte(`{"value":"basilisk"}`), nil
	}
	defer func() { vaultDefaultExec = oldExec }()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/requests", server.handleRequests)
	mux.HandleFunc("/v1/requests/", server.handleRequestByID)

	clientPriv, clientPub, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	var created RemoteRequest
	if err := performJSON(mux, http.MethodPost, "/v1/requests", RemoteRequestCreate{
		Kind:            requestKindVault,
		Agent:           "hermes",
		Profile:         "bsm-fetch",
		Resource:        "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		Reason:          "test",
		VaultRef:        "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		ClientPublicKey: clientPub,
	}, &created); err != nil {
		t.Fatal(err)
	}

	// localDecideRequest fires async — poll the store until status flips.
	deadline := time.Now().Add(2 * time.Second)
	var approved RemoteRequest
	for time.Now().Before(deadline) {
		var got RemoteRequest
		if err := performJSON(mux, http.MethodGet, "/v1/requests/"+url.PathEscape(created.ID), nil, &got); err != nil {
			t.Fatal(err)
		}
		if got.Status != remoteStatusPending {
			approved = got
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if approved.Status != remoteStatusApproved {
		t.Fatalf("expected approved, got %s (message=%s)", approved.Status, approved.Message)
	}
	if approved.EncryptedLease == nil {
		t.Fatal("expected encrypted lease")
	}
	payload, err := decryptLease(clientPriv, *approved.EncryptedLease)
	if err != nil {
		t.Fatal(err)
	}
	if payload.SecretValue != "basilisk" {
		t.Fatalf("expected basilisk in SecretValue, got %q", payload.SecretValue)
	}
	if len(payload.Env) != 0 {
		t.Fatalf("vault payload should not carry env, got %v", payload.Env)
	}
}

func TestPermissionUpgradeRequestPersistsAllFields(t *testing.T) {
	t.Parallel()
	// Regression for the createRequest constructor losing target_profile,
	// target_resource, grant_mode, and original_request_id when copying
	// RemoteRequestCreate -> Request and -> RemoteRequest. Without those
	// fields propagating, validateRequestAt would reject every upgrade
	// request as missing target_profile, and even successful POSTs would
	// store an upgrade record with no target metadata.
	cfg := &Config{
		Profiles: map[string]Profile{
			"permission-upgrade": {
				Kind:       requestKindPermissionUpgrade,
				Agents:     []string{"hermes"},
				Resources:  []string{"k8s-read"},
				TTLSeconds: 60,
			},
			"k8s-read": {
				Agents:          []string{"hermes"},
				Resources:       []string{"namespace/kestrel"},
				TTLSeconds:      60,
				AllowedCommands: [][]string{{"kubectl", "get"}},
			},
		},
	}
	// Permission-upgrade requests require a local-approve daemon (the
	// signed-approver flow can't decide them). The test server simulates
	// the daemon by setting localApprove=true; localDecideRequest leaves
	// upgrade kind pending so we just verify the POST persists fields.
	server := capbrokerServer{
		cfg:          cfg,
		stateDir:     t.TempDir(),
		store:        newRemoteStore(t.TempDir()),
		localApprove: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/requests", server.handleRequests)
	mux.HandleFunc("/v1/requests/", server.handleRequestByID)

	_, clientPub, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	var created RemoteRequest
	if err := performJSON(mux, http.MethodPost, "/v1/requests", RemoteRequestCreate{
		Kind:              requestKindPermissionUpgrade,
		Agent:             "hermes",
		Profile:           "permission-upgrade",
		Resource:          "k8s-read",
		Reason:            "screenshot mission needs API pod logs to diagnose missing thumbnails",
		TargetProfile:     "k8s-read",
		TargetResource:    "namespace/basilisk",
		GrantMode:         grantModeOnce,
		OriginalRequestID: "req_originating_403",
		ClientPublicKey:   clientPub,
	}, &created); err != nil {
		t.Fatalf("upgrade POST should succeed validation, got %v", err)
	}
	if created.TargetProfile != "k8s-read" {
		t.Fatalf("TargetProfile not persisted, got %q", created.TargetProfile)
	}
	if created.TargetResource != "namespace/basilisk" {
		t.Fatalf("TargetResource not persisted, got %q", created.TargetResource)
	}
	if created.GrantMode != grantModeOnce {
		t.Fatalf("GrantMode not persisted, got %q", created.GrantMode)
	}
	if created.OriginalRequestID != "req_originating_403" {
		t.Fatalf("OriginalRequestID not persisted, got %q", created.OriginalRequestID)
	}
}

func TestVaultRequestRejectedWithoutLocalApprove(t *testing.T) {
	t.Parallel()
	// Without --local-approve, an approver CLI handles decisions but its
	// path (approvePendingOnce in remote_approve.go) only knows how to
	// build command-style leases — vault requests would round-trip an
	// empty SecretValue and silently look like success. Reject upfront.
	cfg := &Config{
		Profiles: map[string]Profile{
			"bsm-fetch": {
				Kind:       requestKindVault,
				Vault:      "bsm",
				VaultAuth:  "x",
				Agents:     []string{"hermes"},
				Resources:  []string{"abc"},
				TTLSeconds: 60,
			},
		},
	}
	server := capbrokerServer{
		cfg:          cfg,
		stateDir:     t.TempDir(),
		store:        newRemoteStore(t.TempDir()),
		localApprove: false, // signed-approver mode
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/requests", server.handleRequests)
	mux.HandleFunc("/v1/requests/", server.handleRequestByID)

	_, clientPub, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(RemoteRequestCreate{
		Kind:            requestKindVault,
		Agent:           "hermes",
		Profile:         "bsm-fetch",
		Resource:        "abc",
		VaultRef:        "abc",
		ClientPublicKey: clientPub,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Result().StatusCode, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "vault requests require a local-approve daemon") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
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
