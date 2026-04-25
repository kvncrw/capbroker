// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

const leaseEncryptionAlgorithm = "ecdh-p256+aes-256-gcm"

type ApproverKeyFile struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func writeApproverKey(name, path string) (ApproverKeyFile, error) {
	if name == "" {
		return ApproverKeyFile{}, fmt.Errorf("key name is required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ApproverKeyFile{}, err
	}
	keyFile := ApproverKeyFile{
		Type:       "capbroker-approver-ed25519-v1",
		Name:       name,
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
	}
	if path != "" {
		data, err := json.MarshalIndent(keyFile, "", "  ")
		if err != nil {
			return ApproverKeyFile{}, err
		}
		if err := os.WriteFile(expandHome(path), append(data, '\n'), 0o600); err != nil {
			return ApproverKeyFile{}, err
		}
	}
	return keyFile, nil
}

func readApproverKey(path string) (ApproverKeyFile, ed25519.PrivateKey, error) {
	if path == "" {
		return ApproverKeyFile{}, nil, fmt.Errorf("approver key path is required")
	}
	data, err := os.ReadFile(expandHome(path))
	if err != nil {
		return ApproverKeyFile{}, nil, err
	}
	var keyFile ApproverKeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return ApproverKeyFile{}, nil, fmt.Errorf("parse approver key: %w", err)
	}
	privateBytes, err := base64.StdEncoding.DecodeString(keyFile.PrivateKey)
	if err != nil {
		return ApproverKeyFile{}, nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(privateBytes) != ed25519.PrivateKeySize {
		return ApproverKeyFile{}, nil, fmt.Errorf("private key has invalid length %d", len(privateBytes))
	}
	return keyFile, ed25519.PrivateKey(privateBytes), nil
}

func signDecision(requestID string, decision RemoteDecision, privateKey ed25519.PrivateKey) RemoteDecision {
	decision.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, decisionSigningPayload(requestID, decision)))
	return decision
}

func verifyDecisionSignature(cfg *Config, requestID string, decision RemoteDecision, allowUnsigned bool) error {
	if len(cfg.Remote.Approvers) == 0 {
		if allowUnsigned {
			return nil
		}
		return fmt.Errorf("no remote approvers configured")
	}
	publicKeyText, ok := cfg.Remote.Approvers[decision.Approver]
	if !ok {
		return fmt.Errorf("unknown approver %q", decision.Approver)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(publicKeyText)
	if err != nil {
		return fmt.Errorf("decode approver public key: %w", err)
	}
	if len(publicBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("approver public key has invalid length %d", len(publicBytes))
	}
	signature, err := base64.StdEncoding.DecodeString(decision.Signature)
	if err != nil {
		return fmt.Errorf("decode approval signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicBytes), decisionSigningPayload(requestID, decision), signature) {
		return fmt.Errorf("approval signature verification failed")
	}
	return nil
}

func generateLeaseRecipientKey() (*ecdh.PrivateKey, string, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	publicKey := base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	return privateKey, publicKey, nil
}

func validateLeaseRecipientPublicKey(publicKeyText string) error {
	publicBytes, err := base64.StdEncoding.DecodeString(publicKeyText)
	if err != nil {
		return fmt.Errorf("decode client public key: %w", err)
	}
	if _, err := ecdh.P256().NewPublicKey(publicBytes); err != nil {
		return fmt.Errorf("invalid client public key: %w", err)
	}
	return nil
}

func encryptLeaseForRecipient(publicKeyText string, payload LeasePayload) (*EncryptedLease, error) {
	recipientPublicBytes, err := base64.StdEncoding.DecodeString(publicKeyText)
	if err != nil {
		return nil, fmt.Errorf("decode client public key: %w", err)
	}
	recipientPublicKey, err := ecdh.P256().NewPublicKey(recipientPublicBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid client public key: %w", err)
	}
	senderPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := senderPrivateKey.ECDH(recipientPublicKey)
	if err != nil {
		return nil, err
	}
	key := leaseSymmetricKey(shared)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, []byte(leaseEncryptionAlgorithm))
	return &EncryptedLease{
		Algorithm:       leaseEncryptionAlgorithm,
		SenderPublicKey: base64.StdEncoding.EncodeToString(senderPrivateKey.PublicKey().Bytes()),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptLease(privateKey *ecdh.PrivateKey, encrypted EncryptedLease) (LeasePayload, error) {
	if encrypted.Algorithm != leaseEncryptionAlgorithm {
		return LeasePayload{}, fmt.Errorf("unsupported lease algorithm %q", encrypted.Algorithm)
	}
	senderPublicBytes, err := base64.StdEncoding.DecodeString(encrypted.SenderPublicKey)
	if err != nil {
		return LeasePayload{}, fmt.Errorf("decode sender public key: %w", err)
	}
	senderPublicKey, err := ecdh.P256().NewPublicKey(senderPublicBytes)
	if err != nil {
		return LeasePayload{}, fmt.Errorf("invalid sender public key: %w", err)
	}
	shared, err := privateKey.ECDH(senderPublicKey)
	if err != nil {
		return LeasePayload{}, err
	}
	key := leaseSymmetricKey(shared)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return LeasePayload{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return LeasePayload{}, err
	}
	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return LeasePayload{}, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return LeasePayload{}, fmt.Errorf("decode ciphertext: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(leaseEncryptionAlgorithm))
	if err != nil {
		return LeasePayload{}, err
	}
	var payload LeasePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return LeasePayload{}, fmt.Errorf("parse lease payload: %w", err)
	}
	return payload, nil
}

func leaseSymmetricKey(shared []byte) [32]byte {
	data := make([]byte, 0, len(shared)+len(leaseEncryptionAlgorithm))
	data = append(data, shared...)
	data = append(data, leaseEncryptionAlgorithm...)
	return sha256.Sum256(data)
}
