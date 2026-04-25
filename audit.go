// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type AuditEvent struct {
	Time        time.Time `json:"time"`
	Event       string    `json:"event"`
	Agent       string    `json:"agent,omitempty"`
	Profile     string    `json:"profile,omitempty"`
	Resource    string    `json:"resource,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Command     []string  `json:"command,omitempty"`
	GrantID     string    `json:"grant_id,omitempty"`
	RequestHash string    `json:"request_hash,omitempty"`
	Approved    *bool     `json:"approved,omitempty"`
	ExitCode    *int      `json:"exit_code,omitempty"`
	Message     string    `json:"message,omitempty"`
}

func appendAudit(stateDir string, event AuditEvent) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	event.Time = time.Now().UTC()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	path := filepath.Join(stateDir, "audit.jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}
