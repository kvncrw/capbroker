// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"time"
)

func TestRemoteLeaseEncryptDecrypt(t *testing.T) {
	t.Parallel()
	privateKey, publicKey, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Minute).UTC()
	encrypted, err := encryptLeaseForRecipient(publicKey, LeasePayload{
		Env:       map[string]string{"GH_TOKEN": "secret-token"},
		Files:     map[string]string{"KUBECONFIG": "apiVersion: v1\n"},
		Agent:     "remote-agent",
		Profile:   "github-review",
		Resource:  "example-org/example-repo",
		Command:   []string{"gh", "pr", "view", "142"},
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decryptLease(privateKey, *encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Env["GH_TOKEN"] != "secret-token" {
		t.Fatalf("unexpected token %q", payload.Env["GH_TOKEN"])
	}
	if payload.Files["KUBECONFIG"] != "apiVersion: v1\n" {
		t.Fatalf("unexpected file content %q", payload.Files["KUBECONFIG"])
	}
	if !payload.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected expiry %s", payload.ExpiresAt)
	}
}

func TestRemoteLeaseEncryptDecryptVaultPayload(t *testing.T) {
	t.Parallel()
	privateKey, publicKey, err := generateLeaseRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Minute).UTC()
	// Vault payload: only SecretValue is set; Env/Files empty.
	encrypted, err := encryptLeaseForRecipient(publicKey, LeasePayload{
		Agent:       "hermes",
		Profile:     "bsm-fetch",
		Resource:    "5da84bec-9b21-4e7f-a720-b41b00cad9d5",
		ExpiresAt:   expiresAt,
		SecretValue: "basilisk",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decryptLease(privateKey, *encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if payload.SecretValue != "basilisk" {
		t.Fatalf("unexpected SecretValue %q", payload.SecretValue)
	}
	if len(payload.Env) != 0 || len(payload.Files) != 0 {
		t.Fatal("vault payload should not carry Env or Files")
	}
}

func TestDecisionSignatureVerification(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/approver.key"
	keyFile, err := writeApproverKey("local-authority", path)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := readApproverKey(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Remote: RemoteConfig{Approvers: map[string]string{"local-authority": keyFile.PublicKey}}}
	decision := signDecision("req_test", RemoteDecision{
		Approved: true,
		Approver: "local-authority",
		Message:  "ok",
	}, privateKey)
	if err := verifyDecisionSignature(cfg, "req_test", decision, false); err != nil {
		t.Fatal(err)
	}
	decision.Message = "tampered"
	if err := verifyDecisionSignature(cfg, "req_test", decision, false); err == nil {
		t.Fatal("expected tampered decision to fail verification")
	}
}
